//! The environment a launched child gets (m02-plan U8; ADR-0007 §8).
//!
//! * `SSH_AUTH_SOCK` only when every pair of the binding uses one endpoint;
//! * on Windows, `core.sshCommand=<verified client>` through `GIT_CONFIG_COUNT` only
//!   when Git's selection is the bundled MSYS default, appended after the caller's
//!   entries (a malformed caller count injects nothing);
//! * never overrides a user's `GIT_SSH_COMMAND`, `GIT_SSH` or a `core.sshCommand` at
//!   any scope: those are reported as `ConsumerOverride`s.
//!
//! The child gets the caller's environment plus [`EnvDelta::set`] and nothing else
//! (`a27_cwd_and_env_preserved_plus_only_documented_additions`). Readings applied:
//!
//! * **`SSH_AUTH_SOCK`.** Set to the pairs' common endpoint locator when the binding
//!   has at least one pair, every pair names an endpoint, all are equal, the
//!   transport suits the platform (a Unix socket off Windows, a named pipe on
//!   Windows) and the integration's own `environment` does not name a different
//!   `SSH_AUTH_SOCK`. Otherwise nothing is set, and a caller `SSH_AUTH_SOCK` that
//!   therefore stays in force for a paired binding is reported as an override.
//!   Other `integration.environment` entries are not documented additions and are
//!   not applied. The integration's own overrides (an effective `IdentityAgent`,
//!   F8) are carried through first.
//! * **Git.** The selection's source is reported when it is not Git's default:
//!   `GIT_SSH_COMMAND` and `GIT_SSH` from the environment, `core.sshCommand` at its
//!   scope (a `config` selection without a scope is not reported: no scope can be
//!   named truthfully; nothing is injected either). When the selection says
//!   default but the caller's environment disagrees (`GIT_SSH_COMMAND`, a
//!   `core.sshCommand` among the caller's `GIT_CONFIG_*` entries or in
//!   `GIT_CONFIG_PARAMETERS`, or `GIT_SSH`, in F22 order), the setting actually in
//!   force is reported and nothing is injected.
//! * **Injection (Windows only)** needs, besides the above, the default selection
//!   classified `bundled_msys`, exactly one verified `ssh` executable that renders
//!   under the ADR-0007 §4 `core.sshCommand` rule (absolute drive path, `/`
//!   separators, single-quoted for Git's POSIX shell; no `'`, `"`, control
//!   character or newline), and a well-formed caller `GIT_CONFIG_COUNT`: absent, or
//!   ASCII digits whose `GIT_CONFIG_KEY_<i>`/`GIT_CONFIG_VALUE_<i>` all exist, with
//!   no stale entry at the index Heimdall would use. Anything else (an empty count,
//!   a sign, whitespace, a missing entry) injects nothing. On Windows variable names
//!   compare ASCII case-insensitively.
//!
//! Values are never reported: an override names its setting and source only.

use std::ffi::{OsStr, OsString};

use heimdall_contract::doctor::{GitScope, GitSshClassification, GitSshSelection, GitSshSource};
use heimdall_contract::provider::EndpointKind;
use heimdall_contract::request::{
    ConsumerIntegration, ConsumerKind, ConsumerOverride, OverrideSource,
};
use heimdall_localenv::env::{Env, Platform};

use crate::resolve::ResolvedProgram;

const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";
const GIT_SSH_COMMAND: &str = "GIT_SSH_COMMAND";
const GIT_SSH: &str = "GIT_SSH";
const GIT_CONFIG_COUNT: &str = "GIT_CONFIG_COUNT";
const GIT_CONFIG_PARAMETERS: &str = "GIT_CONFIG_PARAMETERS";
const CORE_SSH_COMMAND: &str = "core.sshCommand";

/// What is added to the caller's environment, and what stays in force instead.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvDelta {
    /// Variables set (names and values; nonsecret: socket paths and Git's command
    /// configuration).
    pub set: Vec<(OsString, OsString)>,
    /// Settings another source keeps in force (names only, never values).
    pub overrides: Vec<ConsumerOverride>,
}

impl EnvDelta {
    /// The delta for `integration` over the caller's `env` and Git `selection`.
    #[must_use]
    pub fn from_integration(
        integration: &ConsumerIntegration,
        env: &Env,
        selection: &GitSshSelection,
        platform: Platform,
    ) -> EnvDelta {
        let mut delta = EnvDelta::default();
        for item in &integration.overrides {
            delta.report(item.clone());
        }

        match agent_socket(integration, platform) {
            Some(locator) => delta
                .set
                .push((OsString::from(SSH_AUTH_SOCK), OsString::from(locator))),
            None if !integration.pairs.is_empty()
                && var(env, SSH_AUTH_SOCK, platform).is_some() =>
            {
                delta.report(ConsumerOverride {
                    consumer: ConsumerKind::Ssh,
                    setting: SSH_AUTH_SOCK.to_owned(),
                    source: OverrideSource::Environment,
                });
            }
            None => {}
        }

        let caller = caller_config(env, platform);
        let in_force = git_in_force(env, selection, &caller, platform);
        let default_selection = in_force.is_none() && selection.source == GitSshSource::Default;
        if let Some(item) = in_force {
            delta.report(item);
        }
        if platform.is_windows()
            && default_selection
            && selection.classification == GitSshClassification::BundledMsys
            && let Some(value) = verified_client_command(integration)
            && let CallerConfig::Entries { count, .. } = caller
        {
            let names = (
                format!("GIT_CONFIG_KEY_{count}"),
                format!("GIT_CONFIG_VALUE_{count}"),
            );
            let stale =
                var(env, &names.0, platform).is_some() || var(env, &names.1, platform).is_some();
            if let (false, Some(next)) = (stale, count.checked_add(1)) {
                delta.set.push((
                    OsString::from(GIT_CONFIG_COUNT),
                    OsString::from(next.to_string()),
                ));
                delta
                    .set
                    .push((OsString::from(names.0), OsString::from(CORE_SSH_COMMAND)));
                delta
                    .set
                    .push((OsString::from(names.1), OsString::from(value)));
            }
        }
        delta
    }

    fn report(&mut self, item: ConsumerOverride) {
        if !self.overrides.contains(&item) {
            self.overrides.push(item);
        }
    }
}

/// The child's command: `program` with `args` (argv[1..]; argv[0] is the resolved
/// path), the caller's environment, working directory and stdio inherited, plus
/// `delta.set`. No shell, no new process group, no job object.
pub(crate) fn child_command(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
) -> std::process::Command {
    let mut command = std::process::Command::new(&program.path);
    command.args(args);
    for (name, value) in &delta.set {
        command.env(name, value);
    }
    command
}

/// A variable of `env`; on Windows the name compares ASCII case-insensitively.
pub(crate) fn var<'a>(env: &'a Env, name: &str, platform: Platform) -> Option<&'a OsStr> {
    if platform.is_windows() {
        env.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    } else {
        env.get(name)
    }
}

/// The pairs' common endpoint locator, when the rule (module docs) allows it.
fn agent_socket(integration: &ConsumerIntegration, platform: Platform) -> Option<String> {
    let mut endpoints = integration.pairs.iter().map(|p| p.endpoint.as_ref());
    let first = endpoints.next()??;
    if endpoints.any(|e| e != Some(first)) {
        return None;
    }
    let suits = match first.kind {
        EndpointKind::UnixSocket => !platform.is_windows(),
        EndpointKind::NamedPipe => platform.is_windows(),
        _ => false,
    };
    if !suits || first.locator.is_empty() || first.locator.contains('\0') {
        return None;
    }
    let disagrees = integration.environment.iter().any(|(name, value)| {
        let same_name = if platform.is_windows() {
            name.eq_ignore_ascii_case(SSH_AUTH_SOCK)
        } else {
            name == SSH_AUTH_SOCK
        };
        same_name && *value != first.locator
    });
    (!disagrees).then(|| first.locator.clone())
}

/// The caller's `GIT_CONFIG_COUNT` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallerConfig {
    /// Well formed (an absent count is zero entries).
    Entries {
        /// How many.
        count: usize,
        /// Whether one of them sets `core.sshCommand`.
        sets_ssh_command: bool,
    },
    /// Anything else: nothing is injected.
    Malformed,
}

fn caller_config(env: &Env, platform: Platform) -> CallerConfig {
    let Some(raw) = var(env, GIT_CONFIG_COUNT, platform) else {
        return CallerConfig::Entries {
            count: 0,
            sets_ssh_command: false,
        };
    };
    let Some(text) = raw.to_str() else {
        return CallerConfig::Malformed;
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return CallerConfig::Malformed;
    }
    let Ok(count) = text.parse::<usize>() else {
        return CallerConfig::Malformed;
    };
    // Each entry needs two variables; a larger count must miss one.
    if count > env.iter().count() / 2 {
        return CallerConfig::Malformed;
    }
    let mut sets_ssh_command = false;
    for i in 0..count {
        let key = var(env, &format!("GIT_CONFIG_KEY_{i}"), platform);
        let value = var(env, &format!("GIT_CONFIG_VALUE_{i}"), platform);
        match (key, value) {
            (Some(key), Some(_)) => {
                sets_ssh_command |= key.eq_ignore_ascii_case(CORE_SSH_COMMAND);
            }
            _ => return CallerConfig::Malformed,
        }
    }
    CallerConfig::Entries {
        count,
        sets_ssh_command,
    }
}

/// The Git setting in force instead of Git's default, if any (module docs).
fn git_in_force(
    env: &Env,
    selection: &GitSshSelection,
    caller: &CallerConfig,
    platform: Platform,
) -> Option<ConsumerOverride> {
    let git = |setting: &str, source: OverrideSource| {
        Some(ConsumerOverride {
            consumer: ConsumerKind::Git,
            setting: setting.to_owned(),
            source,
        })
    };
    match selection.source {
        GitSshSource::Default => {}
        GitSshSource::EnvGitSshCommand => {
            return git(GIT_SSH_COMMAND, OverrideSource::Environment);
        }
        GitSshSource::Config => {
            return selection
                .scope
                .and_then(|scope| git(CORE_SSH_COMMAND, OverrideSource::GitScope { scope }));
        }
        GitSshSource::EnvGitSsh => return git(GIT_SSH, OverrideSource::Environment),
        // A source this build does not know is never Git's default.
        _ => return None,
    }
    // The selection says default; the caller's environment decides in F22 order.
    if var(env, GIT_SSH_COMMAND, platform).is_some() {
        return git(GIT_SSH_COMMAND, OverrideSource::Environment);
    }
    let parameters_set = var(env, GIT_CONFIG_PARAMETERS, platform).is_some_and(|p| {
        p.to_string_lossy()
            .to_ascii_lowercase()
            .contains("sshcommand")
    });
    let entries_set = matches!(
        caller,
        CallerConfig::Entries {
            sets_ssh_command: true,
            ..
        }
    );
    if parameters_set || entries_set {
        return git(
            CORE_SSH_COMMAND,
            OverrideSource::GitScope {
                scope: GitScope::Command,
            },
        );
    }
    if var(env, GIT_SSH, platform).is_some() {
        return git(GIT_SSH, OverrideSource::Environment);
    }
    None
}

/// The `core.sshCommand` value naming the verified client (ADR-0007 §4 rule), when
/// the integration names exactly one `ssh` executable that renders under it.
fn verified_client_command(integration: &ConsumerIntegration) -> Option<String> {
    let mut paths = integration
        .executables
        .iter()
        .filter(|e| e.consumer == ConsumerKind::Ssh)
        .map(|e| e.path.as_str());
    let path = paths.next()?;
    if paths.any(|other| other != path) {
        return None;
    }
    if path
        .chars()
        .any(|c| c == '\'' || c == '"' || c.is_control())
    {
        return None;
    }
    let forward = path.replace('\\', "/");
    let b = forward.as_bytes();
    let drive_absolute = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/';
    drive_absolute.then(|| format!("'{forward}'"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::Timestamp;
    use heimdall_contract::doctor::ConfigProvenance;
    use heimdall_contract::ids::{AccountName, DestinationId, IdentityId};
    use heimdall_contract::provider::{
        EndpointRef, EvidenceBasis, IdentitySelection, InteractionKind, NoninteractiveEligibility,
    };
    use heimdall_contract::request::{ConsumerExecutable, PairIntegration};

    const SYSTEM32_SSH: &str = "C:\\Windows\\System32\\OpenSSH\\ssh.exe";

    fn pair(endpoint: Option<EndpointRef>) -> PairIntegration {
        PairIntegration {
            destination: DestinationId::parse("h1").unwrap(),
            account: AccountName::parse("deploy").unwrap(),
            identity: IdentityId::parse("idn_00112233445566778899aabbccddeeff").unwrap(),
            mechanism: "native_agent".to_owned(),
            endpoint,
            alias: None,
            interaction: InteractionKind::Unknown,
            interaction_basis: EvidenceBasis::Inferred,
            declared_at: None,
            identity_selection: IdentitySelection::Exclusive,
            selection_observed_at: Timestamp::UNIX_EPOCH,
            declaration: None,
            noninteractive: NoninteractiveEligibility {
                eligible: false,
                reason: None,
            },
            eligibility_checked_at: Timestamp::UNIX_EPOCH,
            identity_selection_report: None,
        }
    }

    fn socket(locator: &str) -> Option<EndpointRef> {
        Some(EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: locator.to_owned(),
        })
    }

    fn pipe(locator: &str) -> Option<EndpointRef> {
        Some(EndpointRef {
            kind: EndpointKind::NamedPipe,
            locator: locator.to_owned(),
        })
    }

    fn integration(pairs: Vec<PairIntegration>) -> ConsumerIntegration {
        ConsumerIntegration {
            pairs,
            executables: vec![ConsumerExecutable {
                consumer: ConsumerKind::Ssh,
                path: SYSTEM32_SSH.to_owned(),
                version: None,
                sha256: None,
                basis: EvidenceBasis::Observed,
            }],
            ..ConsumerIntegration::default()
        }
    }

    fn default_msys() -> GitSshSelection {
        GitSshSelection {
            source: GitSshSource::Default,
            scope: None,
            classification: GitSshClassification::BundledMsys,
        }
    }

    fn os(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    fn git(setting: &str, source: OverrideSource) -> ConsumerOverride {
        ConsumerOverride {
            consumer: ConsumerKind::Git,
            setting: setting.to_owned(),
            source,
        }
    }

    fn env(vars: &[(&str, &str)]) -> Env {
        Env::from_vars(vars.iter().copied())
    }

    #[test]
    fn ssh_auth_sock_only_for_one_common_endpoint() {
        let caller = env(&[(SSH_AUTH_SOCK, "/caller/agent.sock")]);
        let sel = default_msys();
        let one = integration(vec![pair(socket("/s/a.sock")), pair(socket("/s/a.sock"))]);
        let d = EnvDelta::from_integration(&one, &caller, &sel, Platform::Linux);
        assert_eq!(d.set, os(&[(SSH_AUTH_SOCK, "/s/a.sock")]));
        assert!(d.overrides.is_empty());

        let sock_override = ConsumerOverride {
            consumer: ConsumerKind::Ssh,
            setting: SSH_AUTH_SOCK.to_owned(),
            source: OverrideSource::Environment,
        };
        for pairs in [
            vec![pair(socket("/s/a.sock")), pair(socket("/s/b.sock"))],
            vec![pair(socket("/s/a.sock")), pair(None)],
            vec![pair(None)],
            vec![pair(pipe("\\\\.\\pipe\\agent"))],
            vec![pair(socket(""))],
        ] {
            let d = EnvDelta::from_integration(&integration(pairs), &caller, &sel, Platform::MacOs);
            assert!(d.set.is_empty(), "{d:?}");
            assert_eq!(d.overrides, vec![sock_override.clone()]);
            // Without a caller value nothing is in force, so nothing is reported.
            let none = EnvDelta::from_integration(
                &integration(vec![pair(socket("/a")), pair(socket("/b"))]),
                &Env::default(),
                &sel,
                Platform::MacOs,
            );
            assert_eq!(none, EnvDelta::default());
        }
        // No pairs: nothing set, nothing reported.
        let d = EnvDelta::from_integration(&integration(vec![]), &caller, &sel, Platform::Linux);
        assert_eq!(d, EnvDelta::default());
    }

    #[test]
    fn ssh_auth_sock_named_pipe_on_windows_and_disagreeing_environment_refused() {
        let sel = GitSshSelection {
            classification: GitSshClassification::VerifiedClient,
            ..default_msys()
        };
        let i = integration(vec![pair(pipe("\\\\.\\pipe\\hm-agent"))]);
        let d = EnvDelta::from_integration(&i, &Env::default(), &sel, Platform::Windows);
        assert_eq!(d.set, os(&[(SSH_AUTH_SOCK, "\\\\.\\pipe\\hm-agent")]));
        let d = EnvDelta::from_integration(
            &integration(vec![pair(socket("/s/a.sock"))]),
            &Env::default(),
            &sel,
            Platform::Windows,
        );
        assert!(d.set.is_empty());

        let mut i = integration(vec![pair(socket("/s/a.sock"))]);
        i.environment = vec![(SSH_AUTH_SOCK.to_owned(), "/s/other.sock".to_owned())];
        let d = EnvDelta::from_integration(&i, &Env::default(), &sel, Platform::Linux);
        assert!(d.set.is_empty());
        i.environment = vec![
            (SSH_AUTH_SOCK.to_owned(), "/s/a.sock".to_owned()),
            ("UNDOCUMENTED".to_owned(), "x".to_owned()),
        ];
        let d = EnvDelta::from_integration(&i, &Env::default(), &sel, Platform::Linux);
        // Only the documented addition.
        assert_eq!(d.set, os(&[(SSH_AUTH_SOCK, "/s/a.sock")]));
    }

    #[test]
    fn integration_overrides_are_carried_first_without_duplicates() {
        let agent = ConsumerOverride {
            consumer: ConsumerKind::Ssh,
            setting: "IdentityAgent".to_owned(),
            source: OverrideSource::SshConfig(ConfigProvenance {
                path_display: "~/.ssh/config".to_owned(),
                line: 4,
            }),
        };
        let mut i = integration(vec![pair(socket("/s/a.sock"))]);
        i.overrides = vec![agent.clone(), agent.clone()];
        let sel = GitSshSelection {
            source: GitSshSource::EnvGitSsh,
            scope: None,
            classification: GitSshClassification::Other,
        };
        let d = EnvDelta::from_integration(&i, &Env::default(), &sel, Platform::Linux);
        assert_eq!(
            d.overrides,
            vec![agent, git(GIT_SSH, OverrideSource::Environment)]
        );
    }

    #[test]
    fn every_non_default_git_selection_is_reported_and_nothing_injected() {
        let local = GitSshSelection {
            source: GitSshSource::Config,
            scope: Some(GitScope::Local),
            classification: GitSshClassification::Other,
        };
        let cases = [
            (
                GitSshSelection {
                    source: GitSshSource::EnvGitSshCommand,
                    scope: None,
                    classification: GitSshClassification::Other,
                },
                Some(git(GIT_SSH_COMMAND, OverrideSource::Environment)),
            ),
            (
                local,
                Some(git(
                    CORE_SSH_COMMAND,
                    OverrideSource::GitScope {
                        scope: GitScope::Local,
                    },
                )),
            ),
            (
                GitSshSelection {
                    source: GitSshSource::EnvGitSsh,
                    scope: None,
                    classification: GitSshClassification::BundledMsys,
                },
                Some(git(GIT_SSH, OverrideSource::Environment)),
            ),
            (
                GitSshSelection {
                    source: GitSshSource::Config,
                    scope: None,
                    classification: GitSshClassification::BundledMsys,
                },
                None,
            ),
        ];
        let i = integration(vec![]);
        for platform in [Platform::Windows, Platform::Linux] {
            for (sel, expected) in &cases {
                let d = EnvDelta::from_integration(&i, &Env::default(), sel, platform);
                assert!(d.set.is_empty(), "{sel:?} {platform:?}");
                assert_eq!(d.overrides, expected.iter().cloned().collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn windows_bundled_msys_default_injects_the_verified_client_through_git_config_count() {
        let i = integration(vec![]);
        let d = EnvDelta::from_integration(&i, &Env::default(), &default_msys(), Platform::Windows);
        assert_eq!(
            d.set,
            os(&[
                (GIT_CONFIG_COUNT, "1"),
                ("GIT_CONFIG_KEY_0", CORE_SSH_COMMAND),
                (
                    "GIT_CONFIG_VALUE_0",
                    "'C:/Windows/System32/OpenSSH/ssh.exe'"
                ),
            ])
        );
        assert!(d.overrides.is_empty());
        // Appended after the caller's entries, which stay untouched.
        let caller = env(&[
            ("git_config_count", "2"),
            ("GIT_CONFIG_KEY_0", "user.name"),
            ("GIT_CONFIG_VALUE_0", "x"),
            ("Git_Config_Key_1", "color.ui"),
            ("GIT_CONFIG_VALUE_1", "auto"),
        ]);
        let d = EnvDelta::from_integration(&i, &caller, &default_msys(), Platform::Windows);
        assert_eq!(
            d.set,
            os(&[
                (GIT_CONFIG_COUNT, "3"),
                ("GIT_CONFIG_KEY_2", CORE_SSH_COMMAND),
                (
                    "GIT_CONFIG_VALUE_2",
                    "'C:/Windows/System32/OpenSSH/ssh.exe'"
                ),
            ])
        );
    }

    #[test]
    fn git_run_malformed_caller_git_config_count_injects_nothing() {
        let i = integration(vec![]);
        let complete = [("GIT_CONFIG_KEY_0", "a.b"), ("GIT_CONFIG_VALUE_0", "c")];
        for count in [
            "",
            "x",
            "-1",
            "+1",
            " 1",
            "1 ",
            "0x1",
            "2",
            "99999999999999999999999",
        ] {
            let mut vars = vec![(GIT_CONFIG_COUNT, count)];
            vars.extend(complete);
            let d = EnvDelta::from_integration(&i, &env(&vars), &default_msys(), Platform::Windows);
            assert!(d.set.is_empty(), "count {count:?}: {d:?}");
            assert!(d.overrides.is_empty(), "count {count:?}");
        }
        // A missing value, and a stale entry at the index Heimdall would use.
        for vars in [
            vec![(GIT_CONFIG_COUNT, "1"), ("GIT_CONFIG_KEY_0", "a.b")],
            vec![
                (GIT_CONFIG_COUNT, "1"),
                ("GIT_CONFIG_KEY_0", "a.b"),
                ("GIT_CONFIG_VALUE_0", "c"),
                ("GIT_CONFIG_KEY_1", "stale"),
            ],
        ] {
            let d = EnvDelta::from_integration(&i, &env(&vars), &default_msys(), Platform::Windows);
            assert!(d.set.is_empty(), "{vars:?}");
        }
        // "0" is well formed.
        let d = EnvDelta::from_integration(
            &i,
            &env(&[(GIT_CONFIG_COUNT, "0")]),
            &default_msys(),
            Platform::Windows,
        );
        assert_eq!(d.set.len(), 3);
    }

    #[test]
    fn caller_environment_that_contradicts_a_default_selection_wins_and_blocks_injection() {
        let i = integration(vec![]);
        let command = OverrideSource::GitScope {
            scope: GitScope::Command,
        };
        let cases: Vec<(Vec<(&str, &str)>, ConsumerOverride)> = vec![
            (
                vec![(GIT_SSH_COMMAND, ""), (GIT_SSH, "x")],
                git(GIT_SSH_COMMAND, OverrideSource::Environment),
            ),
            (
                vec![
                    (GIT_CONFIG_COUNT, "1"),
                    ("GIT_CONFIG_KEY_0", "Core.SSHCommand"),
                    ("GIT_CONFIG_VALUE_0", "v"),
                    (GIT_SSH, "x"),
                ],
                git(CORE_SSH_COMMAND, command.clone()),
            ),
            (
                vec![(GIT_CONFIG_PARAMETERS, "'core.sshcommand'='v'")],
                git(CORE_SSH_COMMAND, command),
            ),
            (
                vec![("git_ssh", "x")],
                git(GIT_SSH, OverrideSource::Environment),
            ),
        ];
        for (vars, expected) in cases {
            let d = EnvDelta::from_integration(&i, &env(&vars), &default_msys(), Platform::Windows);
            assert!(d.set.is_empty(), "{vars:?}");
            assert_eq!(d.overrides, vec![expected], "{vars:?}");
        }
    }

    #[test]
    fn unix_never_injects_for_git() {
        let i = integration(vec![]);
        for platform in [Platform::Linux, Platform::MacOs, Platform::OtherUnix] {
            let d = EnvDelta::from_integration(&i, &Env::default(), &default_msys(), platform);
            assert_eq!(d, EnvDelta::default());
        }
    }

    #[test]
    fn injection_needs_bundled_msys_and_one_renderable_verified_client() {
        let sel_other = GitSshSelection {
            classification: GitSshClassification::Undetermined,
            ..default_msys()
        };
        let d = EnvDelta::from_integration(
            &integration(vec![]),
            &Env::default(),
            &sel_other,
            Platform::Windows,
        );
        assert_eq!(d, EnvDelta::default());
        for path in [
            "C:\\it's\\ssh.exe",
            "C:\\a\"b\\ssh.exe",
            "C:\\a\nb\\ssh.exe",
            "\\\\server\\share\\ssh.exe",
            "ssh.exe",
            "C:",
        ] {
            let mut i = integration(vec![]);
            i.executables[0].path = path.to_owned();
            let d =
                EnvDelta::from_integration(&i, &Env::default(), &default_msys(), Platform::Windows);
            assert!(d.set.is_empty(), "{path:?}");
        }
        let mut i = integration(vec![]);
        i.executables.push(ConsumerExecutable {
            consumer: ConsumerKind::Ssh,
            path: "C:\\Other\\ssh.exe".to_owned(),
            version: None,
            sha256: None,
            basis: EvidenceBasis::Observed,
        });
        let d = EnvDelta::from_integration(&i, &Env::default(), &default_msys(), Platform::Windows);
        assert!(d.set.is_empty(), "two different verified clients");
        let mut i = integration(vec![]);
        i.executables.clear();
        let d = EnvDelta::from_integration(&i, &Env::default(), &default_msys(), Platform::Windows);
        assert!(d.set.is_empty(), "no verified client");
    }

    #[test]
    fn git_run_never_records_child_arguments_or_config_values() {
        // Built at run time, never committed as a literal value.
        let canary = ["HEIMDALL", "CANARY", "GIT", &std::process::id().to_string()].join("_");
        let caller = env(&[
            (GIT_SSH_COMMAND, &canary),
            (GIT_CONFIG_COUNT, "1"),
            ("GIT_CONFIG_KEY_0", CORE_SSH_COMMAND),
            ("GIT_CONFIG_VALUE_0", &canary),
            (SSH_AUTH_SOCK, &canary),
        ]);
        let i = integration(vec![pair(socket("/a")), pair(socket("/b"))]);
        for platform in [Platform::Windows, Platform::Linux] {
            let d = EnvDelta::from_integration(&i, &caller, &default_msys(), platform);
            assert!(d.set.is_empty());
            let text = format!("{:?}", d.overrides);
            assert!(
                !text.contains(&canary),
                "a configuration value reached an override"
            );
            assert_eq!(d.overrides.len(), 2);
        }
    }
}
