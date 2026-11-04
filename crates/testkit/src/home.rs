//! Scratch directories, the scratch home, isolation arguments and the default-identity
//! guard (m02-plan §0 "Fixtures and the owner's material", U7; ADR-0007 §9, F1, F19,
//! F20; M2-D09).
//!
//! * [`Scratch`] is a temporary directory this process created. It is removed on drop,
//!   pass or fail (unwinding drops it too). Removal is `remove_dir_all` of that one
//!   directory, which never follows a symlink, so only paths created inside it go.
//! * [`ScratchHome`] lays out a scratch home and starts the **decoy counting agent**
//!   that every client command gets as `SSH_AUTH_SOCK` (ADR-0007 §9 item 2).
//! * [`ScratchHome::isolation_args`] is the only thing a test puts on a client's
//!   command line: `-F`, `UserKnownHostsFile`, `GlobalKnownHostsFile` and `BatchMode`.
//!   Never `IdentityAgent`, `IdentityFile`, `IdentitiesOnly`, `HostName`, `User` or
//!   `Port`: command-line values win (F1) and would bypass the configuration under test.
//! * [`ScratchHome::client_command`] applies the **default-identity guard** first. It
//!   evaluates the alias statically with `heimdall-sshconf` (which executes nothing)
//!   under every invocation the command may make (a shell, a remote command, Git's
//!   remote command, the `sftp` subsystem) and every session type a `SessionType`
//!   directive in the tree can give (ADR-0007 §12.16 item 2), and refuses with
//!   [`FixtureUnsafe`] unless, in each evaluation, the alias's identity list certainly
//!   has an entry and every entry is a scratch path. Otherwise ssh would add its
//!   default identity files, which come from the account home (F19, F20): the owner's
//!   keys.
//!   The guard also refuses an `IdentityAgent` that names anything but `none`,
//!   `SSH_AUTH_SOCK` (the decoy) or a fixture endpoint, so a client never reaches the
//!   owner's agents (m02-plan §0).
//!
//! The guard reads configuration only through [`ScratchSource`], which refuses every
//! path outside the scratch root before touching the filesystem. Its account home is a
//! sentinel outside scratch, so a `~` path is never a scratch path and never read.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use heimdall_sshconf::directive::{Keyword, KnownKeyword};
use heimdall_sshconf::eval::{
    Candidate, Evaluation, Invocation, OpenSshVersion, Query, Resolved, UnresolvedReason, Value,
    evaluate,
};
use heimdall_sshconf::include::{ConfigSet, ConfigSource, Roots, SourceBytes, SourceError};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::parse::Line;

use crate::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig};

/// A temporary directory owned by this process, removed on drop.
#[derive(Debug)]
pub struct Scratch {
    dir: tempfile::TempDir,
    next: AtomicU32,
}

impl Scratch {
    /// Create `hm-XXXXXX` under the system temporary directory (owner-only on Unix).
    ///
    /// # Errors
    /// The directory cannot be created.
    pub fn new() -> io::Result<Scratch> {
        let dir = tempfile::Builder::new().prefix("hm-").tempdir()?;
        set_owner_only_dir(dir.path())?;
        Ok(Scratch {
            dir,
            next: AtomicU32::new(1),
        })
    }

    /// The root.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Create a fresh, owner-only subdirectory `<root>/<prefix><n>` and return it.
    /// Names stay short so Unix socket paths fit the platform limit.
    ///
    /// # Errors
    /// The directory cannot be created.
    pub fn subdir(&self, prefix: &str) -> io::Result<PathBuf> {
        loop {
            let n = self.next.fetch_add(1, Ordering::Relaxed);
            let path = self.path().join(format!("{prefix}{n}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    set_owner_only_dir(&path)?;
                    return Ok(path);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Whether `path` is lexically inside this scratch root (absolute, no `.` or `..`
    /// component). Touches no filesystem.
    #[must_use]
    pub fn contains_lexically(&self, path: &Path) -> bool {
        lexically_under(path, self.path())
    }
}

/// Owner-only permissions on a directory this fixture created (Unix `0700`; on Windows
/// the temporary directory already inherits the profile's owner-only ACL).
fn set_owner_only_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Write a new file with owner-only permissions (`0600` on Unix). Fails if it exists.
pub(crate) fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// `path` is absolute, has no `.`/`..` component, and starts with `root`.
fn lexically_under(path: &Path, root: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        && path.starts_with(root)
}

/// Find a program: each `PATH` entry, then the usual system directories. `None` when
/// absent. Never runs anything.
#[must_use]
pub fn find_program(name: &str) -> Option<PathBuf> {
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if cfg!(unix) {
        for d in [
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
        ] {
            dirs.push(PathBuf::from(d));
        }
    }
    dirs.into_iter()
        .filter(|d| d.is_absolute())
        .map(|d| d.join(&file))
        .find(|p| p.is_file())
}

/// The OpenSSH client version (`ssh -V`), parsed once; [`OpenSshVersion::MINIMUM`]
/// when it cannot be read.
#[must_use]
pub fn client_version() -> OpenSshVersion {
    static VERSION: OnceLock<OpenSshVersion> = OnceLock::new();
    *VERSION.get_or_init(|| {
        let Some(ssh) = find_program("ssh") else {
            return OpenSshVersion::MINIMUM;
        };
        let out = Command::new(ssh)
            .arg("-V")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        out.ok()
            .and_then(|o| {
                let mut text = String::from_utf8_lossy(&o.stderr).into_owned();
                text.push_str(&String::from_utf8_lossy(&o.stdout));
                parse_openssh_version(&text)
            })
            .unwrap_or(OpenSshVersion::MINIMUM)
    })
}

/// Parse `OpenSSH_10.3p1, …` or `OpenSSH_for_Windows_9.5p2, …`.
#[must_use]
pub fn parse_openssh_version(text: &str) -> Option<OpenSshVersion> {
    let start = text.find("OpenSSH_")? + "OpenSSH_".len();
    let rest = &text[start..];
    let rest = rest.strip_prefix("for_Windows_").unwrap_or(rest);
    let digits = |s: &str| -> (Option<u16>, usize) {
        let n = s.bytes().take_while(u8::is_ascii_digit).count();
        (s[..n].parse().ok(), n)
    };
    let (major, n) = digits(rest);
    let rest = rest[n..].strip_prefix('.')?;
    let (minor, n) = digits(rest);
    let rest = &rest[n..];
    let portable = rest.strip_prefix('p').and_then(|r| digits(r).0);
    Some(OpenSshVersion {
        major: major?,
        minor: minor?,
        portable,
    })
}

/// Which client [`ScratchHome::client_command`] builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKind {
    /// `ssh <isolation> <alias>`; the caller appends the remote command.
    Ssh,
    /// `scp <isolation>`; the caller appends sources and `alias:target`.
    Scp,
    /// `sftp <isolation>`; the caller appends options (`-b`), then the alias.
    Sftp,
    /// `git` with `GIT_SSH_COMMAND` = `ssh <isolation>`, a scratch `HOME`,
    /// `GIT_CONFIG_NOSYSTEM=1` and a scratch `GIT_CONFIG_GLOBAL`; the caller appends
    /// the Git command and `alias:path` (m02-plan §0).
    Git,
}

impl ClientKind {
    /// Every kind.
    pub const ALL: [ClientKind; 4] = [
        ClientKind::Ssh,
        ClientKind::Scp,
        ClientKind::Sftp,
        ClientKind::Git,
    ];

    fn program(self) -> &'static str {
        match self {
            ClientKind::Ssh => "ssh",
            ClientKind::Scp => "scp",
            ClientKind::Sftp => "sftp",
            ClientKind::Git => "git",
        }
    }
}

/// Why the default-identity guard refused to build a client command (ADR-0007 §9
/// item 3). Messages carry no path: a refused entry may name the owner's home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureUnsafe {
    /// No `IdentityFile` certainly applies to the alias, so ssh may add its default
    /// identity files from the account home (F19, F20).
    DefaultIdentities,
    /// `IdentityFile` entry `index` (evaluation order) is not a scratch path.
    NonScratchIdentity {
        /// Entry index.
        index: usize,
    },
    /// `IdentityAgent` candidate `index` names an agent that is not `none`,
    /// `SSH_AUTH_SOCK` (the decoy) or a fixture endpoint.
    NonScratchAgent {
        /// Candidate index.
        index: usize,
    },
    /// Part of the configuration tree could not be read (an unreadable include or an
    /// exceeded bound), so not every identity is known.
    Unreadable,
    /// The alias is not a plain host token (empty, starts with `-`, or contains
    /// whitespace or a control character).
    BadAlias,
}

impl fmt::Display for FixtureUnsafe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixtureUnsafe::DefaultIdentities => f.write_str(
                "fixture unsafe: no IdentityFile certainly applies, so ssh would add the \
                 account home's default identities",
            ),
            FixtureUnsafe::NonScratchIdentity { index } => {
                write!(
                    f,
                    "fixture unsafe: IdentityFile entry {index} is not a scratch path"
                )
            }
            FixtureUnsafe::NonScratchAgent { index } => write!(
                f,
                "fixture unsafe: IdentityAgent candidate {index} is not a fixture agent"
            ),
            FixtureUnsafe::Unreadable => {
                f.write_str("fixture unsafe: part of the configuration tree could not be read")
            }
            FixtureUnsafe::BadAlias => f.write_str("fixture unsafe: the alias is not a host token"),
        }
    }
}

impl std::error::Error for FixtureUnsafe {}

/// What the guard accepts as "scratch": the root as created and its canonical form,
/// plus the fixture endpoints.
#[derive(Debug, Clone)]
pub struct GuardScope {
    roots: Vec<PathBuf>,
    canonical_root: PathBuf,
}

impl GuardScope {
    /// The scope of one scratch root.
    ///
    /// # Errors
    /// The root cannot be canonicalized.
    pub fn new(root: &Path) -> io::Result<GuardScope> {
        let canonical_root = fs::canonicalize(root)?;
        let mut roots = vec![root.to_path_buf()];
        if canonical_root != root {
            roots.push(canonical_root.clone());
        }
        Ok(GuardScope {
            roots,
            canonical_root,
        })
    }

    /// Whether an `IdentityFile` argument (as written) is a scratch path: no `%` or
    /// `${` token and no `~` (their values are not scratch), absolute, no `.`/`..`,
    /// under the root; and, where it or an ancestor exists, its canonical form is
    /// under the canonical root (no symlink out). Nothing outside scratch is touched.
    #[must_use]
    pub fn is_scratch_path(&self, arg: &str) -> bool {
        if arg.contains('%') || arg.contains("${") || arg.starts_with('~') {
            return false;
        }
        let path = Path::new(arg);
        if !self.roots.iter().any(|r| lexically_under(path, r)) {
            return false;
        }
        // Inside the root lexically: resolve the deepest existing ancestor.
        let mut probe = path;
        loop {
            match fs::canonicalize(probe) {
                Ok(c) => return c.starts_with(&self.canonical_root),
                Err(_) => match probe.parent() {
                    Some(parent) => probe = parent,
                    None => return false,
                },
            }
        }
    }

    /// Whether an `IdentityAgent` argument (as written) keeps the client on fixture
    /// agents: `none`, `SSH_AUTH_SOCK` / `$SSH_AUTH_SOCK` / `${SSH_AUTH_SOCK}` (the
    /// decoy), a scratch socket path, or a fixture pipe (`\\.\pipe\heimdall-hmtest-…`).
    #[must_use]
    pub fn is_fixture_agent(&self, arg: &str) -> bool {
        arg.eq_ignore_ascii_case("none")
            || matches!(arg, "SSH_AUTH_SOCK" | "$SSH_AUTH_SOCK" | "${SSH_AUTH_SOCK}")
            || crate::agent::is_fixture_pipe_name(arg)
            || self.is_scratch_path(arg)
    }
}

/// The guard's decision over one static evaluation (pure apart from resolving scratch
/// paths). See the module documentation.
///
/// # Errors
/// [`FixtureUnsafe`].
pub fn judge_evaluation(evaluation: &Evaluation, scope: &GuardScope) -> Result<(), FixtureUnsafe> {
    if evaluation.unresolved.iter().any(|u| {
        matches!(
            u.reason,
            UnresolvedReason::IncludeUnreadable | UnresolvedReason::BoundExceeded
        )
    }) {
        return Err(FixtureUnsafe::Unreadable);
    }
    let identities: &[Candidate] = evaluation
        .accumulated
        .get(&KnownKeyword::IdentityFile)
        .map_or(&[], Vec::as_slice);
    if !identities.iter().any(|c| c.determined) {
        return Err(FixtureUnsafe::DefaultIdentities);
    }
    for (index, candidate) in identities.iter().enumerate() {
        if !single_arg(&candidate.value).is_some_and(|a| scope.is_scratch_path(a)) {
            return Err(FixtureUnsafe::NonScratchIdentity { index });
        }
    }
    let agents: Vec<&Value> = match evaluation.values.get(&KnownKeyword::IdentityAgent) {
        None | Some(Resolved::Unset) => Vec::new(),
        Some(Resolved::Determined(v)) => vec![v],
        Some(Resolved::Undetermined(vs)) => vs.iter().collect(),
    };
    for (index, value) in agents.into_iter().enumerate() {
        if !single_arg(value).is_some_and(|a| scope.is_fixture_agent(a)) {
            return Err(FixtureUnsafe::NonScratchAgent { index });
        }
    }
    Ok(())
}

fn single_arg(value: &Value) -> Option<&str> {
    match value.args.as_slice() {
        [one] => Some(one.as_str()),
        _ => None,
    }
}

/// The read-only [`ConfigSource`] the guard evaluates through. Every path is checked
/// lexically against the scratch root **before** any filesystem call, then again after
/// canonicalization; anything outside is `PermissionDenied`. The account home is a
/// sentinel outside scratch that is never read.
#[derive(Debug)]
pub struct ScratchSource {
    scope: GuardScope,
    home_sentinel: PathBuf,
    user_dir: PathBuf,
    system_dir: PathBuf,
    env: BTreeMap<String, String>,
    limits: Limits,
}

impl ScratchSource {
    /// A source confined to `scope`, answering `${VAR}` only from `env`.
    #[must_use]
    pub fn new(scope: GuardScope, env: BTreeMap<String, String>) -> ScratchSource {
        let top = scope
            .canonical_root
            .ancestors()
            .last()
            .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
        let home_sentinel = top.join("hm-fixture-account-home-sentinel");
        ScratchSource {
            user_dir: home_sentinel.join(".ssh"),
            system_dir: home_sentinel.join("system-ssh-dir-sentinel"),
            home_sentinel,
            scope,
            env,
            limits: Limits::default(),
        }
    }

    fn admit(&self, path: &Path) -> Result<PathBuf, SourceError> {
        if !self.scope.roots.iter().any(|r| lexically_under(path, r)) {
            return Err(SourceError::PermissionDenied);
        }
        let canonical = fs::canonicalize(path).map_err(map_io)?;
        if !canonical.starts_with(&self.scope.canonical_root) {
            return Err(SourceError::PermissionDenied);
        }
        Ok(canonical)
    }
}

fn map_io(e: io::Error) -> SourceError {
    match e.kind() {
        io::ErrorKind::NotFound => SourceError::NotFound,
        io::ErrorKind::PermissionDenied => SourceError::PermissionDenied,
        other => SourceError::Io(format!("{other:?}")),
    }
}

impl ConfigSource for ScratchSource {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        let canonical = self.admit(path)?;
        let meta = fs::metadata(&canonical).map_err(map_io)?;
        if !meta.is_file() {
            return Err(SourceError::NotRegular);
        }
        if meta.len() > self.limits.file_bytes as u64 {
            return Err(SourceError::BoundExceeded);
        }
        let bytes = fs::read(&canonical).map_err(map_io)?;
        if bytes.len() > self.limits.file_bytes {
            return Err(SourceError::BoundExceeded);
        }
        Ok(SourceBytes { canonical, bytes })
    }

    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        if !self.scope.roots.iter().any(|r| lexically_under(pattern, r)) {
            return Err(SourceError::PermissionDenied);
        }
        let text = pattern
            .to_str()
            .ok_or_else(|| SourceError::Io("pattern is not UTF-8".to_owned()))?;
        let entries = glob::glob(text).map_err(|e| SourceError::Io(e.msg.to_owned()))?;
        let mut out = Vec::new();
        for entry in entries {
            let path = entry.map_err(|e| map_io(e.into()))?;
            if self.admit(&path).is_ok() {
                out.push(path);
            }
            if out.len() > self.limits.glob_results {
                return Err(SourceError::BoundExceeded);
            }
        }
        out.sort_by(|a, b| {
            a.as_os_str()
                .as_encoded_bytes()
                .cmp(b.as_os_str().as_encoded_bytes())
        });
        Ok(out)
    }

    fn account_home(&self) -> &Path {
        &self.home_sentinel
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

/// A scratch home for client tests (m02-plan U7 `home::ScratchHome`).
///
/// Layout under the scratch root: `home/` (the scratch `HOME`, also [`git_home`]),
/// `home/.ssh/{config,known_hosts}` (both created empty), `empty_known_hosts`,
/// `config/` and `state/` (Heimdall's directories for the env-gated test
/// configuration). A decoy counting [`FakeAgent`] with no keys serves `SSH_AUTH_SOCK`.
///
/// [`git_home`]: ScratchHome::git_home
#[derive(Debug)]
pub struct ScratchHome {
    /// The scratch root.
    pub root: PathBuf,
    /// The scratch user configuration, passed as `-F` (created empty).
    pub user_config: PathBuf,
    /// `<home>/.ssh`.
    pub ssh_dir: PathBuf,
    /// The scratch `UserKnownHostsFile` (created empty).
    pub known_hosts: PathBuf,
    /// The empty `GlobalKnownHostsFile`.
    pub global_known_hosts: PathBuf,
    /// Heimdall's configuration directory for the test configuration.
    pub config_dir: PathBuf,
    /// Heimdall's state directory for the test configuration.
    pub state_dir: PathBuf,
    /// The scratch `HOME` given to clients, agents and Git; holds an empty
    /// `.gitconfig` that `GIT_CONFIG_GLOBAL` names.
    pub git_home: PathBuf,
    /// The decoy counting agent (no keys). Declared before `scratch`, so it stops
    /// before the directory is removed.
    decoy: FakeAgent,
    scratch: Scratch,
}

impl ScratchHome {
    /// Create the layout and start the decoy agent.
    ///
    /// # Panics
    /// When the scratch directory or the decoy agent cannot be created (a broken test
    /// host; a fixture never continues half-built).
    #[must_use]
    pub fn new() -> ScratchHome {
        match ScratchHome::try_new() {
            Ok(home) => home,
            Err(e) => panic!("ScratchHome::new failed: {e}"),
        }
    }

    /// [`new`](Self::new) without the panic.
    ///
    /// # Errors
    /// The layout or the decoy agent cannot be created.
    pub fn try_new() -> io::Result<ScratchHome> {
        let scratch = Scratch::new()?;
        let root = scratch.path().to_path_buf();
        let git_home = root.join("home");
        let ssh_dir = git_home.join(".ssh");
        let config_dir = root.join("config");
        let state_dir = root.join("state");
        for dir in [&git_home, &ssh_dir, &config_dir, &state_dir] {
            fs::create_dir(dir)?;
            set_owner_only_dir(dir)?;
        }
        let user_config = ssh_dir.join("config");
        let known_hosts = ssh_dir.join("known_hosts");
        let global_known_hosts = root.join("empty_known_hosts");
        for file in [&user_config, &known_hosts, &global_known_hosts] {
            write_owner_only(file, b"")?;
        }
        write_owner_only(&git_home.join(".gitconfig"), b"")?;
        let decoy = FakeAgent::try_start(
            Endpoint::in_scratch(&scratch, "decoy")?,
            FakeAgentConfig {
                keys: Vec::new(),
                mode: AgentMode::Normal,
            },
        )?;
        Ok(ScratchHome {
            root,
            user_config,
            ssh_dir,
            known_hosts,
            global_known_hosts,
            config_dir,
            state_dir,
            git_home,
            decoy,
            scratch,
        })
    }

    /// The scratch directory, for starting further fixtures inside the same root.
    #[must_use]
    pub fn scratch(&self) -> &Scratch {
        &self.scratch
    }

    /// The decoy counting agent at `SSH_AUTH_SOCK` (ADR-0007 §9 item 2). Projection,
    /// A01 and A35 tests assert zero contacts here.
    #[must_use]
    pub fn decoy_agent(&self) -> &FakeAgent {
        &self.decoy
    }

    /// Write the scratch user configuration (replaces its content).
    ///
    /// # Errors
    /// The write fails.
    pub fn write_user_config(&self, text: &str) -> io::Result<()> {
        fs::write(&self.user_config, text)
    }

    /// Append a known-hosts line (for example [`crate::sshd::LoopbackSshd::host_key_line`]).
    ///
    /// # Errors
    /// The write fails.
    pub fn trust_host_key(&self, line: &str) -> io::Result<()> {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&self.known_hosts)?;
        writeln!(f, "{line}")
    }

    /// The isolation arguments for a non-interactive client: exactly `-F <user
    /// config>`, `-o UserKnownHostsFile=…`, `-o GlobalKnownHostsFile=…` and `-o
    /// BatchMode=yes` (m02-plan §0; ADR-0007 §9 item 1).
    #[must_use]
    pub fn isolation_args(&self) -> Vec<OsString> {
        let mut args = self.interactive_isolation_args();
        args.push("-o".into());
        args.push("BatchMode=yes".into());
        args
    }

    /// [`isolation_args`](Self::isolation_args) without `BatchMode`, for tests that
    /// drive a client through a pty.
    #[must_use]
    pub fn interactive_isolation_args(&self) -> Vec<OsString> {
        vec![
            "-F".into(),
            self.user_config.clone().into_os_string(),
            "-o".into(),
            format!("UserKnownHostsFile={}", ssh_option_path(&self.known_hosts)).into(),
            "-o".into(),
            format!(
                "GlobalKnownHostsFile={}",
                ssh_option_path(&self.global_known_hosts)
            )
            .into(),
        ]
    }

    /// Run the default-identity guard for `alias` (see the module documentation).
    ///
    /// The command this guards may run a remote command, a subsystem or Git, and the
    /// caller appends what it runs after the guard, so the alias is evaluated under
    /// **every** invocation ([`guard_invocations`]: `Shell`, `Exec(None)`,
    /// `Exec(Some(<sentinel>))` and `Subsystem("sftp")`), and under each of those again
    /// with each session type a `SessionType` directive in the tree can give forced
    /// first (as `-o SessionType=…` or `-N` would). It refuses when any one evaluation
    /// fails the guard (ADR-0007 §12.16 item 2).
    ///
    /// # Errors
    /// [`FixtureUnsafe`]: the first refusal, in that order.
    pub fn check_alias(&self, alias: &str) -> Result<(), FixtureUnsafe> {
        if alias.is_empty()
            || alias.starts_with('-')
            || alias.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(FixtureUnsafe::BadAlias);
        }
        let scope = GuardScope::new(&self.root).map_err(|_| FixtureUnsafe::Unreadable)?;
        let mut env = BTreeMap::new();
        if let Some(sock) = self.decoy.endpoint().locator().to_str() {
            env.insert("SSH_AUTH_SOCK".to_owned(), sock.to_owned());
        }
        if let Some(home) = self.git_home.to_str() {
            env.insert("HOME".to_owned(), home.to_owned());
        }
        let source = ScratchSource::new(scope.clone(), env);
        let roots = Roots::new(Some(self.user_config.clone()), None);
        let query = |invocation: Invocation| Query {
            host: alias.to_owned(),
            user: None,
            local_user: local_user_name(),
            client_version: client_version(),
            invocation,
        };
        let mut session_types = BTreeSet::new();
        for invocation in guard_invocations() {
            let mut set = ConfigSet::new();
            let evaluation = evaluate(
                &mut set,
                &source,
                &roots,
                &query(invocation),
                &Limits::default(),
            );
            judge_evaluation(&evaluation, &scope)?;
            session_types.extend(session_types_in(&set, &evaluation));
        }
        for session_type in session_types {
            let forced = ForcedSessionType {
                inner: &source,
                user_config: &self.user_config,
                line: format!("SessionType {session_type}\n"),
            };
            for invocation in guard_invocations() {
                let mut set = ConfigSet::new();
                let evaluation = evaluate(
                    &mut set,
                    &forced,
                    &roots,
                    &query(invocation),
                    &Limits::default(),
                );
                judge_evaluation(&evaluation, &scope)?;
            }
        }
        Ok(())
    }

    /// The client command for `alias`, after the default-identity guard, with only the
    /// isolation arguments on its command line, `SSH_AUTH_SOCK` set to the decoy
    /// agent, `HOME` set to the scratch home and the Git isolation variables set. See
    /// [`ClientKind`] for where the caller puts the alias.
    ///
    /// # Errors
    /// [`FixtureUnsafe`].
    pub fn client_command(&self, kind: ClientKind, alias: &str) -> Result<Command, FixtureUnsafe> {
        self.build_client(kind, alias, self.isolation_args())
    }

    /// [`client_command`](Self::client_command) without `BatchMode`, for pty tests.
    ///
    /// # Errors
    /// [`FixtureUnsafe`].
    pub fn interactive_client_command(
        &self,
        kind: ClientKind,
        alias: &str,
    ) -> Result<Command, FixtureUnsafe> {
        self.build_client(kind, alias, self.interactive_isolation_args())
    }

    fn build_client(
        &self,
        kind: ClientKind,
        alias: &str,
        isolation: Vec<OsString>,
    ) -> Result<Command, FixtureUnsafe> {
        self.check_alias(alias)?;
        let program = |name: &str| {
            find_program(name).map_or_else(|| OsString::from(name), PathBuf::into_os_string)
        };
        let mut cmd = Command::new(program(kind.program()));
        match kind {
            ClientKind::Ssh => {
                cmd.args(&isolation).arg(alias);
            }
            ClientKind::Scp | ClientKind::Sftp => {
                cmd.args(&isolation);
            }
            ClientKind::Git => {
                let mut words = vec![program("ssh")];
                words.extend(isolation);
                cmd.env("GIT_SSH_COMMAND", sh_join(&words))
                    .env("GIT_SSH_VARIANT", "ssh")
                    .env("GIT_TERMINAL_PROMPT", "0");
            }
        }
        cmd.env("SSH_AUTH_SOCK", self.decoy.endpoint().locator())
            .env("HOME", &self.git_home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.git_home.join(".gitconfig"))
            .env_remove("GIT_SSH")
            .env_remove("GIT_CONFIG_SYSTEM")
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .env_remove("SSH_AGENT_PID");
        if kind != ClientKind::Git {
            cmd.env_remove("GIT_SSH_COMMAND");
        }
        Ok(cmd)
    }
}

impl Default for ScratchHome {
    fn default() -> Self {
        ScratchHome::new()
    }
}

/// The remote command the guard's `Exec(Some(_))` evaluation uses: a name no fixture
/// configuration matches on purpose. `Exec(None)` covers every other command, since
/// its `Match command` is undecided.
pub const GUARD_EXEC_SENTINEL: &str = "hm-fixture-guard-sentinel-command";

/// Every invocation [`ScratchHome::check_alias`] evaluates (ADR-0007 §12.16 item 2):
/// a shell, a remote command that is not known, the sentinel remote command, and the
/// `sftp` subsystem (sftp, scp's SFTP mode).
#[must_use]
pub fn guard_invocations() -> [Invocation; 4] {
    [
        Invocation::Shell,
        Invocation::Exec(None),
        Invocation::Exec(Some(GUARD_EXEC_SENTINEL.to_owned())),
        Invocation::Subsystem("sftp".to_owned()),
    ]
}

/// The session types the `SessionType` directives of every file `evaluation` read can
/// give, lower-cased (`none`, `subsystem`, `default`). A value that is not a plain word
/// is left out: ssh refuses such a line wherever it is, so no client runs with it.
fn session_types_in(set: &ConfigSet, evaluation: &Evaluation) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for id in evaluation.files.keys() {
        let Some(file) = set.file(*id) else { continue };
        for line in &file.lines {
            if let Line::Directive(d) = line
                && d.keyword == Keyword::Known(KnownKeyword::SessionType)
                && let Some(value) = d.args.first()
                && !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_alphabetic())
            {
                out.insert(value.to_ascii_lowercase());
            }
        }
    }
    out
}

/// The guard's source with one `SessionType` line read first: the user configuration
/// is served with `line` in front (after a byte-order mark, when it has one), so the
/// value is in force before any configured one, as a command-line `-o SessionType=…`
/// is (F1). Every other read goes to `inner` unchanged; nothing is written.
struct ForcedSessionType<'a> {
    inner: &'a ScratchSource,
    user_config: &'a Path,
    line: String,
}

impl ConfigSource for ForcedSessionType<'_> {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        let mut got = self.inner.read(path)?;
        if path == self.user_config {
            const BOM: &[u8] = b"\xEF\xBB\xBF";
            let (bom, rest) = if got.bytes.starts_with(BOM) {
                got.bytes.split_at(BOM.len())
            } else {
                (&[][..], got.bytes.as_slice())
            };
            let mut bytes = Vec::with_capacity(got.bytes.len() + self.line.len());
            bytes.extend_from_slice(bom);
            bytes.extend_from_slice(self.line.as_bytes());
            bytes.extend_from_slice(rest);
            got.bytes = bytes;
        }
        Ok(got)
    }

    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        self.inner.glob(pattern)
    }

    fn account_home(&self) -> &Path {
        self.inner.account_home()
    }

    fn user_dir(&self) -> &Path {
        self.inner.user_dir()
    }

    fn system_dir(&self) -> &Path {
        self.inner.system_dir()
    }

    fn env(&self, name: &str) -> Option<String> {
        self.inner.env(name)
    }

    fn include_home(&self) -> Option<&Path> {
        self.inner.include_home()
    }
}

/// The local account name for `%u` and `Match localuser`, read at run time and never
/// logged; `None` when unknown, so the guard's evaluation leaves only the conditions
/// that read it undetermined (ADR-0007 §12.28 item 3), never an empty name.
fn local_user_name() -> Option<String> {
    ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// A path as the value of an ssh `-o Key=value` option: `%` doubled (token
/// expansion), and double-quoted with `\`/`"` escaped when it holds whitespace, a
/// quote or a backslash (OpenSSH argument splitting).
#[must_use]
pub fn ssh_option_path(path: &Path) -> String {
    let text = path.to_string_lossy().replace('%', "%%");
    if text
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\'' || c == '\\')
    {
        ssh_config_quote(&text)
    } else {
        text
    }
}

/// One `ssh_config` argument token: double-quoted, with `\` and `"` escaped (OpenSSH
/// 8.7+ argument splitting). `%` is **not** touched; see [`ssh_option_path`].
#[must_use]
pub fn ssh_config_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// POSIX `sh` single-quoting of one word.
#[must_use]
pub fn sh_quote(word: &OsStr) -> String {
    let text = word.to_string_lossy();
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Join words into one `sh` command line.
#[must_use]
pub fn sh_join(words: &[OsString]) -> String {
    words
        .iter()
        .map(|w| sh_quote(w))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_sshconf::eval::{Candidate, Value};
    use heimdall_sshconf::parse::{SourceId, Span};

    fn value(arg: &str) -> Value {
        Value::new(
            vec![arg.to_owned()],
            Span {
                source: SourceId(0),
                line: 1,
            },
            None,
        )
    }

    fn eval_with(ids: &[(&str, bool)], agent: Option<Resolved>) -> Evaluation {
        let mut e = Evaluation::default();
        if !ids.is_empty() {
            e.accumulated.insert(
                KnownKeyword::IdentityFile,
                ids.iter()
                    .map(|(a, d)| Candidate {
                        value: value(a),
                        determined: *d,
                    })
                    .collect(),
            );
        }
        if let Some(a) = agent {
            e.values.insert(KnownKeyword::IdentityAgent, a);
        }
        e
    }

    #[test]
    fn judge_refuses_empty_list_tilde_outside_and_undetermined_only() {
        let s = Scratch::new().unwrap();
        let scope = GuardScope::new(s.path()).unwrap();
        let inside = s.path().join("k.pub");
        let inside = inside.to_str().unwrap();
        assert_eq!(
            judge_evaluation(&eval_with(&[], None), &scope),
            Err(FixtureUnsafe::DefaultIdentities)
        );
        assert_eq!(
            judge_evaluation(&eval_with(&[(inside, false)], None), &scope),
            Err(FixtureUnsafe::DefaultIdentities)
        );
        assert_eq!(
            judge_evaluation(
                &eval_with(&[(inside, true), ("~/.ssh/id_ed25519", true)], None),
                &scope
            ),
            Err(FixtureUnsafe::NonScratchIdentity { index: 1 })
        );
        let outside = std::env::temp_dir().join("hm-not-scratch").join("k.pub");
        assert_eq!(
            judge_evaluation(
                &eval_with(&[(outside.to_str().unwrap(), true)], None),
                &scope
            ),
            Err(FixtureUnsafe::NonScratchIdentity { index: 0 })
        );
        let dotdot = format!("{}/../x/k.pub", s.path().display());
        assert_eq!(
            judge_evaluation(&eval_with(&[(&dotdot, true)], None), &scope),
            Err(FixtureUnsafe::NonScratchIdentity { index: 0 })
        );
        let token = format!("{}/%u.pub", s.path().display());
        assert_eq!(
            judge_evaluation(&eval_with(&[(&token, true)], None), &scope),
            Err(FixtureUnsafe::NonScratchIdentity { index: 0 })
        );
        // Control: a determined scratch entry, plus an undetermined scratch entry.
        assert_eq!(
            judge_evaluation(&eval_with(&[(inside, true), (inside, false)], None), &scope),
            Ok(())
        );
    }

    #[test]
    fn judge_refuses_unreadable_tree_and_foreign_agent() {
        use heimdall_sshconf::eval::Unresolved;
        let s = Scratch::new().unwrap();
        let scope = GuardScope::new(s.path()).unwrap();
        let inside = s.path().join("k.pub");
        let inside = inside.to_str().unwrap();
        let mut e = eval_with(&[(inside, true)], None);
        e.unresolved.push(Unresolved {
            reason: UnresolvedReason::IncludeUnreadable,
            span: Span {
                source: SourceId(0),
                line: 2,
            },
        });
        assert_eq!(judge_evaluation(&e, &scope), Err(FixtureUnsafe::Unreadable));

        let foreign = Resolved::Determined(value("~/.agent/agent.sock"));
        assert_eq!(
            judge_evaluation(&eval_with(&[(inside, true)], Some(foreign)), &scope),
            Err(FixtureUnsafe::NonScratchAgent { index: 0 })
        );
        let mixed = Resolved::Undetermined(vec![value("none"), value("/run/other/agent")]);
        assert_eq!(
            judge_evaluation(&eval_with(&[(inside, true)], Some(mixed)), &scope),
            Err(FixtureUnsafe::NonScratchAgent { index: 1 })
        );
        for (case, ok) in ["none", "SSH_AUTH_SOCK", "$SSH_AUTH_SOCK", inside]
            .into_iter()
            .enumerate()
        {
            let a = Resolved::Determined(value(ok));
            assert_eq!(
                judge_evaluation(&eval_with(&[(inside, true)], Some(a)), &scope),
                Ok(()),
                "case {case}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn scratch_path_through_symlink_out_is_refused() {
        let s = Scratch::new().unwrap();
        let other = Scratch::new().unwrap();
        let link = s.path().join("link");
        std::os::unix::fs::symlink(other.path(), &link).unwrap();
        let scope = GuardScope::new(s.path()).unwrap();
        assert!(!scope.is_scratch_path(link.join("k.pub").to_str().unwrap()));
        assert!(scope.is_scratch_path(s.path().join("absent/k.pub").to_str().unwrap()));
    }

    #[test]
    fn scratch_source_refuses_outside_paths_before_reading() {
        let s = Scratch::new().unwrap();
        fs::write(s.path().join("cfg"), b"Host x\n").unwrap();
        let src = ScratchSource::new(GuardScope::new(s.path()).unwrap(), BTreeMap::new());
        assert_eq!(src.read(&s.path().join("cfg")).unwrap().bytes, b"Host x\n");
        assert_eq!(
            src.read(&src.account_home().join(".ssh/config")),
            Err(SourceError::PermissionDenied)
        );
        assert_eq!(
            src.read(Path::new("relative")),
            Err(SourceError::PermissionDenied)
        );
        assert!(!src.account_home().starts_with(s.path()));
        assert_eq!(src.env("PATH"), None);
    }

    #[test]
    fn version_parsing() {
        let v = parse_openssh_version("OpenSSH_10.3p1, LibreSSL 3.3.6").unwrap();
        assert_eq!((v.major, v.minor, v.portable), (10, 3, Some(1)));
        let v = parse_openssh_version("OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2").unwrap();
        assert_eq!((v.major, v.minor, v.portable), (9, 5, Some(2)));
        let v = parse_openssh_version("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5").unwrap();
        assert_eq!((v.major, v.minor), (9, 6));
        assert_eq!(parse_openssh_version("garbage"), None);
    }

    #[test]
    fn quoting() {
        assert_eq!(sh_quote(OsStr::new("a'b")), r"'a'\''b'");
        assert_eq!(ssh_config_quote(r#"C:\x "y""#), r#""C:\\x \"y\"""#);
        assert_eq!(ssh_option_path(Path::new("/tmp/a%b")), "/tmp/a%%b");
        assert_eq!(ssh_option_path(Path::new("/tmp/a b")), "\"/tmp/a b\"");
    }
}
