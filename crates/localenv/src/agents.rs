//! Passive agent endpoint detection (m02-plan U3; ADR-0007 §7).
//!
//! Detection opens nothing: it reads `SSH_AUTH_SOCK`, the `IdentityAgent` references
//! in the configuration, and, on Windows, lists `\\.\pipe\` with `std::fs::read_dir`.
//! No 1Password path is hardcoded: the pinned vendor excerpts are not available
//! (docs/sources/excerpts/notes.md, "G03-S12"), so 1Password is recognized only through
//! those two references (ADR-0007 §7; m02-plan U0).
//!
//! * `SSH_AUTH_SOCK` comes from the [`Env`] snapshot, never the live environment.
//! * `IdentityAgent` references are read from every file of the user and system trees
//!   (through [`BoundedSource`], so the same bounds and the same "regular files only"
//!   rule apply), whatever `Host`/`Match` section they are in. `none` and
//!   `SSH_AUTH_SOCK` name no new endpoint. `$NAME` and `${NAME}` take the variable from
//!   the snapshot; `~` and `%d` are the account home (F19); a value with any other
//!   token cannot be located statically and is left to the per-alias evaluation.
//! * Presence on Unix is one `stat` (following a symlink as `connect` would): a socket
//!   owned by our UID is present, a socket owned by another UID is
//!   `ForeignOwner` (never connected to), anything else is `Unknown`. On Windows a pipe
//!   is present when its name is listed.
//! * Which provider serves an endpoint cannot be established passively: every
//!   detected endpoint is `ProviderKind::Unknown` (F18 for the Windows system pipe; no
//!   1Password path is pinned). A catalog identity names its provider.

use std::path::{Path, PathBuf};

use heimdall_contract::doctor::ConfigProvenance;
use heimdall_contract::provider::ProviderKind;
use heimdall_sshconf::directive::{Keyword, KnownKeyword};
use heimdall_sshconf::include::{self, ConfigSet, IncludeVisitor, Roots, Visit};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::parse::Line;

use crate::env::{Env, Platform};
use crate::fs::BoundedSource;
use crate::paths::SshPaths;

/// The Windows OpenSSH agent service's pipe name (ADR-0007 F13, F18).
pub const WINDOWS_SYSTEM_AGENT_PIPE: &str = "openssh-ssh-agent";

/// Most `\\.\pipe\` names read (the listing is bounded).
pub const MAX_PIPE_NAMES: usize = 65_536;

/// Where an agent listens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointLocator {
    /// A Unix socket.
    UnixSocket(PathBuf),
    /// A Windows named pipe (`\\.\pipe\<name>`).
    NamedPipe(String),
}

impl EndpointLocator {
    /// The bounded agent client's locator for this endpoint (ADR-0007 §12.15 item 6,
    /// E-U6-2).
    #[must_use]
    pub fn to_agent_locator(&self) -> heimdall_ipc::agent_client::AgentLocator {
        match self {
            EndpointLocator::UnixSocket(p) => {
                heimdall_ipc::agent_client::AgentLocator::UnixSocket(p.clone())
            }
            EndpointLocator::NamedPipe(n) => {
                heimdall_ipc::agent_client::AgentLocator::NamedPipe(n.clone())
            }
        }
    }

    /// A display form: the socket path with `~` for `home`, or `\\.\pipe\<name>`.
    #[must_use]
    pub fn display(&self, home: &Path) -> String {
        match self {
            EndpointLocator::UnixSocket(p) => crate::paths::display_path(home, p),
            EndpointLocator::NamedPipe(n) => n.clone(),
        }
    }
}

/// Whether the endpoint was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Presence {
    /// The socket or pipe exists.
    Present,
    /// It does not.
    Absent,
    /// It exists but is owned by another user (`agent_endpoint_foreign_owner`).
    ForeignOwner,
    /// It could not be checked.
    Unknown,
}

/// What pointed at the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointSource {
    /// `SSH_AUTH_SOCK`.
    SshAuthSock,
    /// An `IdentityAgent` directive.
    IdentityAgent(heimdall_contract::doctor::ConfigProvenance),
    /// The Windows system pipe `openssh-ssh-agent`.
    WindowsSystemPipe,
}

/// One detected agent endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEndpoint {
    /// Which provider it is believed to be.
    pub provider: ProviderKind,
    /// Where it listens.
    pub locator: EndpointLocator,
    /// Whether it was seen.
    pub presence: Presence,
    /// What pointed at it.
    pub source: EndpointSource,
}

/// Detect agent endpoints passively.
#[must_use]
pub fn detect_agents(env: &Env, paths: &SshPaths, platform: Platform) -> Vec<AgentEndpoint> {
    let pipes = if platform.is_windows() {
        list_pipes()
    } else {
        None
    };
    let mut out: Vec<AgentEndpoint> = Vec::new();
    let mut push = |locator: EndpointLocator, source: EndpointSource| {
        if out
            .iter()
            .any(|e| e.locator == locator && e.source == source)
        {
            return;
        }
        let presence = presence(&locator, pipes.as_deref(), platform);
        out.push(AgentEndpoint {
            provider: ProviderKind::Unknown,
            locator,
            presence,
            source,
        });
    };
    if let Some(sock) = env.get("SSH_AUTH_SOCK").and_then(|v| v.to_str())
        && !sock.is_empty()
        && let Some(locator) = locator_for(sock, platform)
    {
        push(locator, EndpointSource::SshAuthSock);
    }
    for (locator, provenance) in identity_agent_references(env, paths, platform) {
        push(locator, EndpointSource::IdentityAgent(provenance));
    }
    if platform.is_windows()
        && pipes.as_deref().is_some_and(|names| {
            names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(WINDOWS_SYSTEM_AGENT_PIPE))
        })
    {
        push(
            EndpointLocator::NamedPipe(format!(r"\\.\pipe\{WINDOWS_SYSTEM_AGENT_PIPE}")),
            EndpointSource::WindowsSystemPipe,
        );
    }
    out
}

/// The locator a socket path or pipe reference names on `platform`: on Windows
/// `\\.\pipe\<name>` and `//./pipe/<name>` (any case of `pipe`) are pipes; on Unix an
/// absolute path is a socket. Anything else names no endpoint.
#[must_use]
pub fn locator_for(value: &str, platform: Platform) -> Option<EndpointLocator> {
    if platform.is_windows() {
        let lower = value.to_ascii_lowercase();
        for prefix in [r"\\.\pipe\", "//./pipe/"] {
            if lower.starts_with(prefix) {
                let name = &value[prefix.len()..];
                if name.is_empty() || name.contains(['\\', '/']) {
                    return None;
                }
                return Some(EndpointLocator::NamedPipe(format!(r"\\.\pipe\{name}")));
            }
        }
        return None;
    }
    // A Unix absolute path is a leading `/`. `Path::is_absolute` would answer for the
    // host's rules, so a Linux/macOS `platform` evaluated on a Windows host (no drive
    // letter) would name no socket; on a Unix host the two are the same test.
    value
        .starts_with('/')
        .then(|| EndpointLocator::UnixSocket(PathBuf::from(value)))
}

fn presence(locator: &EndpointLocator, pipes: Option<&[String]>, platform: Platform) -> Presence {
    match locator {
        EndpointLocator::UnixSocket(path) if !platform.is_windows() => socket_presence(path),
        EndpointLocator::NamedPipe(name) if platform.is_windows() => {
            let bare = name.strip_prefix(r"\\.\pipe\").unwrap_or(name);
            match pipes {
                Some(names) if names.iter().any(|n| n.eq_ignore_ascii_case(bare)) => {
                    Presence::Present
                }
                Some(_) => Presence::Absent,
                None => Presence::Unknown,
            }
        }
        _ => Presence::Unknown,
    }
}

#[cfg(unix)]
fn socket_presence(path: &Path) -> Presence {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Presence::Absent,
        Err(_) => Presence::Unknown,
        Ok(m) if !m.file_type().is_socket() => Presence::Unknown,
        Ok(m) if m.uid() != crate::sys::current_uid() => Presence::ForeignOwner,
        Ok(_) => Presence::Present,
    }
}

#[cfg(not(unix))]
fn socket_presence(_path: &Path) -> Presence {
    Presence::Unknown
}

/// The names under `\\.\pipe\` (Windows), bounded; `None` when they cannot be listed.
/// Nothing is opened: `read_dir` enumerates names only.
#[cfg(windows)]
fn list_pipes() -> Option<Vec<String>> {
    let entries = std::fs::read_dir(r"\\.\pipe\").ok()?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.ok()?;
        names.push(entry.file_name().to_string_lossy().into_owned());
        if names.len() >= MAX_PIPE_NAMES {
            return None;
        }
    }
    Some(names)
}

#[cfg(not(windows))]
fn list_pipes() -> Option<Vec<String>> {
    None
}

struct AgentRefs {
    found: Vec<(String, PathBuf, u32)>,
}

impl IncludeVisitor for AgentRefs {
    fn line(&mut self, visit: &Visit, line: &Line) {
        if let Line::Directive(d) = line
            && d.keyword == Keyword::Known(KnownKeyword::IdentityAgent)
            && let Some(arg) = d.args.first()
        {
            self.found
                .push((arg.clone(), visit.canonical.clone(), d.span.line));
        }
    }
}

/// The roots OpenSSH reads for `paths`: each file only when an entry exists at its
/// path (a missing file is skipped by ssh; an unreadable one is kept so the walk
/// reports it).
#[must_use]
pub fn roots_for(paths: &SshPaths, read_system: bool) -> Roots {
    let exists = |p: &Path| match std::fs::symlink_metadata(p) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    };
    Roots::new(
        exists(&paths.user_config).then(|| paths.user_config.clone()),
        (read_system && exists(&paths.system_config)).then(|| paths.system_config.clone()),
    )
}

/// Every `IdentityAgent` value in the user and system trees that names an endpoint
/// statically, with where it was written.
#[must_use]
pub fn identity_agent_references(
    env: &Env,
    paths: &SshPaths,
    platform: Platform,
) -> Vec<(EndpointLocator, ConfigProvenance)> {
    let source = BoundedSource::new(paths.clone(), env.clone(), Limits::default());
    let roots = roots_for(paths, true);
    let mut set = ConfigSet::new();
    let mut refs = AgentRefs { found: Vec::new() };
    include::walk(&mut set, &source, &roots, &Limits::default(), &mut refs);
    let mut out = Vec::new();
    for (value, file, line) in refs.found {
        let Some(expanded) = expand_agent_value(&value, &source, env) else {
            continue;
        };
        let Some(locator) = locator_for(&expanded, platform) else {
            continue;
        };
        out.push((
            locator,
            ConfigProvenance {
                path_display: paths.display(&file),
                line,
            },
        ));
    }
    out
}

/// Expand an `IdentityAgent` value statically (module documentation); `None` for
/// `none`, `SSH_AUTH_SOCK`, an unset variable or a token that is not known.
#[must_use]
pub fn expand_agent_value(value: &str, source: &BoundedSource, env: &Env) -> Option<String> {
    use heimdall_sshconf::include::ConfigSource;
    if value.eq_ignore_ascii_case("none") || value == "SSH_AUTH_SOCK" {
        return None;
    }
    if let Some(name) = value.strip_prefix('$')
        && !name.starts_with('{')
    {
        let v = env.get(name)?.to_str()?.to_owned();
        return (!v.is_empty()).then_some(v);
    }
    let expanded = include::expand(value, KnownKeyword::IdentityAgent, source, &|_| None).ok()?;
    if let Some(rest) = expanded.strip_prefix('~') {
        if rest.is_empty() {
            return Some(source.account_home().to_string_lossy().into_owned());
        }
        let rest = rest.strip_prefix(['/', '\\'])?;
        return Some(
            source
                .account_home()
                .join(rest)
                .to_string_lossy()
                .into_owned(),
        );
    }
    Some(expanded)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn locators_follow_the_platform_rules() {
        assert_eq!(
            locator_for("//./pipe/hm-agent", Platform::Windows),
            Some(EndpointLocator::NamedPipe(r"\\.\pipe\hm-agent".into()))
        );
        assert_eq!(
            locator_for(r"\\.\PIPE\hm-agent", Platform::Windows),
            Some(EndpointLocator::NamedPipe(r"\\.\pipe\hm-agent".into()))
        );
        assert_eq!(locator_for("//./pipe/", Platform::Windows), None);
        assert_eq!(locator_for("/tmp/a.sock", Platform::Windows), None);
        assert_eq!(
            locator_for("/tmp/a.sock", Platform::Linux),
            Some(EndpointLocator::UnixSocket("/tmp/a.sock".into()))
        );
        assert_eq!(locator_for("relative.sock", Platform::MacOs), None);
    }

    #[test]
    fn agent_locator_conversion_keeps_the_endpoint() {
        use heimdall_ipc::agent_client::AgentLocator;
        assert_eq!(
            EndpointLocator::UnixSocket("/s/a.sock".into()).to_agent_locator(),
            AgentLocator::UnixSocket("/s/a.sock".into())
        );
        assert_eq!(
            EndpointLocator::NamedPipe(r"\\.\pipe\x".into()).to_agent_locator(),
            AgentLocator::NamedPipe(r"\\.\pipe\x".into())
        );
    }

    #[cfg(unix)]
    #[test]
    fn detection_stats_sockets_and_reads_identity_agent_references_without_connecting() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let ssh = home.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let live = dir.path().join("live.sock");
        let listener = UnixListener::bind(&live).unwrap();
        listener.set_nonblocking(true).unwrap();
        let conf_d = ssh.join("conf.d");
        std::fs::create_dir_all(&conf_d).unwrap();
        std::fs::write(
            ssh.join("config"),
            format!(
                "Include {}/*.conf\nHost a\n  IdentityAgent none\nHost b\n  IdentityAgent ${{HM_AGENT}}\nHost c\n  IdentityAgent %d/missing.sock\nHost d\n  IdentityAgent /x/%h.sock\n",
                conf_d.display()
            ),
        )
        .unwrap();
        std::fs::write(
            conf_d.join("10.conf"),
            "Match host e\n  IdentityAgent ~/gone.sock\n",
        )
        .unwrap();
        let paths = SshPaths::with_test_override(home.clone(), dir.path().join("etc"));
        let env = Env::from_vars([
            ("SSH_AUTH_SOCK", live.clone().into_os_string()),
            ("HM_AGENT", live.clone().into_os_string()),
        ]);
        let found = detect_agents(&env, &paths, Platform::current());
        assert_eq!(found[0].source, EndpointSource::SshAuthSock);
        assert_eq!(found[0].presence, Presence::Present);
        assert_eq!(found[0].provider, ProviderKind::Unknown);
        let refs: Vec<_> = found
            .iter()
            .filter_map(|e| match &e.source {
                EndpointSource::IdentityAgent(p) => Some((e.locator.clone(), e.presence, p.line)),
                _ => None,
            })
            .collect();
        assert_eq!(
            refs,
            vec![
                (
                    EndpointLocator::UnixSocket(home.join("gone.sock")),
                    Presence::Absent,
                    2
                ),
                (
                    EndpointLocator::UnixSocket(live.clone()),
                    Presence::Present,
                    5
                ),
                (
                    EndpointLocator::UnixSocket(home.join("missing.sock")),
                    Presence::Absent,
                    7
                ),
            ]
        );
        // Nothing connected: the listener has no pending connection.
        assert!(listener.accept().is_err());
        // A regular file is not an endpoint.
        let file = dir.path().join("file.sock");
        std::fs::write(&file, b"").unwrap();
        let env = Env::from_vars([("SSH_AUTH_SOCK", file.into_os_string())]);
        let found = detect_agents(&env, &paths, Platform::current());
        assert_eq!(found[0].presence, Presence::Unknown);
    }
}
