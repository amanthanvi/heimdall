//! ⟨M06 U3⟩ Dependencies by construction (ADR-0012 §4.5, §4.6; A24): runner work starts from
//! a clean environment holding only an explicit inventory of runner-owned sources, and an
//! agent outside that inventory is never claimed for unattended readiness.
//!
//! * **The inventory** ([`RunnerInventory`]): the runner signer's own endpoint, runner-local
//!   key files adopted as existing access, and local signers verified as independently managed
//!   (each with its provenance).
//! * **Clean launch** ([`clean_environment`], [`clean_command`]): the child's environment is
//!   cleared and rebuilt from **the declared pass-list** ([`PASS_LIST`], ADR-0012 §4 item 5
//!   ⟨2026-11-22⟩: the only variables copied from the launching process's environment), a
//!   fixed `PATH`, the **launcher-set values** ([`LAUNCHER_SET`]: `HOME`, `USER`, `LOGNAME`
//!   and `SHELL` from the account database, never from the parent; `LANG=C.UTF-8` when the
//!   parent has no `LANG`), and `SSH_AUTH_SOCK` **only** when the inventory names a signer
//!   for it (its value is the inventory's, never the parent's). Nothing else is inherited,
//!   so a socket the management session brought along (an inherited controller socket)
//!   never reaches runner work.
//! * **Provenance** ([`classify_agent`]): the runner's own signer is `runner_managed`; an
//!   inventoried verified signer is `independently_managed`; an agent the runner's own process
//!   inherited from an SSH session is a `controller_dependency`; **any other agent is
//!   `unknown`**, including an ordinary local path that may relay to the controller. A path's
//!   shape is never evidence: [`path_diagnostic`] names what a path looks like for the doctor
//!   and nothing else.
//! * **The claim** ([`unattended_claim`]): only `runner_managed` and `independently_managed`
//!   may back unattended readiness; the others are refused `CAPABILITY_UNAVAILABLE` with
//!   `controller_dependency` or `dependency_provenance_unknown`.
//!
//! **⟨M06 W5⟩ The call site** ([`plan_launch`]): `heimdall run` (and `run
//! --parent-binding`) on an installation of kind `remote_runner` launches its child with
//! exactly the planned environment (the launching process's own is cleared), reports every
//! agent it did not pass with its provenance, and refuses an unattended launch whose binding
//! depends on an agent that is neither runner-managed nor independently managed. On any
//! other installation nothing here is called and the launch is unchanged.
//!
//! * **The inventory of a launch** is built from the binding alone: the runner signer's
//!   endpoints are the managed pairs' endpoints that lie under this installation's own
//!   endpoint directory. No product record verifies a local signer as independently managed
//!   yet, so that list is empty and every other agent is `unknown` or a
//!   `controller_dependency`.
//! * **The pass-list's installation locators** name where this installation's own runtime
//!   is, so work that calls `heimdall` (or an alias whose `ProxyCommand` is the route
//!   helper) reaches the same runtime. No variable of the list carries authority.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use heimdall_app::OpError;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::reason;

/// The `PATH` runner work starts with (system directories only; never inherited).
pub const CLEAN_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// ⟨M06 W5; ADR-0012 §4 item 5 "The declared pass-list" ⟨2026-11-22⟩⟩ **The** variables
/// work launched on a runner (`run`, `run --parent-binding`, `connect`) receives from its
/// parent environment, copied verbatim when present; nothing else is:
///
/// * the installation locators (`crate::paths::Paths` reads exactly these):
///   `HEIMDALL_HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`;
/// * `TERM`, `TZ`, `LANG`, `LC_ALL`.
///
/// None carries authority. `SSH_AUTH_SOCK` is never on it. Adding a variable is an explicit
/// change to this constant and to the ADR's list; a test asserts the exact set.
pub const PASS_LIST: [&str; 8] = [
    crate::paths::HOME_ENV,
    "XDG_CONFIG_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "TERM",
    "TZ",
    "LANG",
    "LC_ALL",
];

/// ⟨M06 W5; ADR-0012 §4 item 5 "Launcher-set values" ⟨2026-11-22⟩⟩ The variables the
/// launcher of runner work sets from the account database
/// ([`crate::platform::account_entry`]: `getpwuid_r` of the current uid), never from the
/// parent: whatever the parent holds under these names does not reach the work. When the
/// account has no usable entry none of them is set (nothing is guessed, and the parent's
/// values still do not pass).
pub const LAUNCHER_SET: [&str; 4] = ["HOME", "USER", "LOGNAME", "SHELL"];

/// The `LANG` the launcher sets when the parent has none (the same bullet). A parent's own
/// `LANG` passes through [`PASS_LIST`].
pub const DEFAULT_LANG: &str = "C.UTF-8";

/// The agent socket variable.
pub const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

/// Where an agent's custody is managed, as far as the runner can establish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyProvenance {
    /// The runner's own signer (K_env in its memory).
    RunnerManaged,
    /// A local signer the owner verified as independently managed on the runner (not a relay).
    IndependentlyManaged,
    /// An agent socket inherited from the SSH session that started the runner's process: it
    /// leads back to the controller.
    ControllerDependency,
    /// Anything else, including an ordinary local path that may relay to the controller.
    Unknown,
}

/// One verified local signer of the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigner {
    /// Its socket path.
    pub socket: PathBuf,
    /// Its provenance: `runner_managed` or `independently_managed` (anything else is never
    /// inventoried).
    pub provenance: DependencyProvenance,
}

/// The explicit inventory of runner-owned sources (module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunnerInventory {
    /// The runner signer's endpoint for this work, if any.
    pub own_signer: Option<PathBuf>,
    /// Runner-local key files adopted as existing access.
    pub adopted_key_files: Vec<PathBuf>,
    /// Local signers verified as independently managed.
    pub verified_signers: Vec<VerifiedSigner>,
}

impl RunnerInventory {
    /// The signer `SSH_AUTH_SOCK` names for runner work: the runner's own, else the first
    /// verified independently managed one; `None`: no agent at all.
    #[must_use]
    pub fn agent_socket(&self) -> Option<&Path> {
        self.own_signer.as_deref().or_else(|| {
            self.verified_signers
                .iter()
                .find(|s| s.provenance == DependencyProvenance::IndependentlyManaged)
                .map(|s| s.socket.as_path())
        })
    }
}

/// How an agent candidate reached the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentOrigin {
    /// Inherited by the runner's own process from an SSH session (`SSH_CONNECTION` or
    /// `SSH_CLIENT` set beside `SSH_AUTH_SOCK`).
    InheritedFromSshSession,
    /// Inherited from a local login or another process.
    InheritedLocal,
    /// Named in configuration or by a request.
    Configured,
}

/// An agent socket some runner work could use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCandidate {
    /// The socket path.
    pub socket: PathBuf,
    /// How it reached the runner.
    pub origin: AgentOrigin,
}

/// The agent the runner's own process inherited, read through `var` (the process environment
/// in production; a fixture in tests).
#[must_use]
pub fn inherited_agent(var: impl Fn(&str) -> Option<OsString>) -> Option<AgentCandidate> {
    let socket = var(SSH_AUTH_SOCK).filter(|s| !s.is_empty())?;
    let from_ssh = ["SSH_CONNECTION", "SSH_CLIENT"]
        .iter()
        .any(|v| var(v).is_some_and(|s| !s.is_empty()));
    Some(AgentCandidate {
        socket: PathBuf::from(socket),
        origin: if from_ssh {
            AgentOrigin::InheritedFromSshSession
        } else {
            AgentOrigin::InheritedLocal
        },
    })
}

/// The provenance of `candidate` against `inventory` (module docs). Only an exact inventory
/// entry is ever claimed; a path's shape plays no part.
#[must_use]
pub fn classify_agent(
    candidate: &AgentCandidate,
    inventory: &RunnerInventory,
) -> DependencyProvenance {
    if inventory.own_signer.as_deref() == Some(candidate.socket.as_path()) {
        return DependencyProvenance::RunnerManaged;
    }
    if let Some(v) = inventory
        .verified_signers
        .iter()
        .find(|v| v.socket == candidate.socket)
    {
        return match v.provenance {
            DependencyProvenance::RunnerManaged | DependencyProvenance::IndependentlyManaged => {
                v.provenance
            }
            _ => DependencyProvenance::Unknown,
        };
    }
    match candidate.origin {
        AgentOrigin::InheritedFromSshSession => DependencyProvenance::ControllerDependency,
        AgentOrigin::InheritedLocal | AgentOrigin::Configured => DependencyProvenance::Unknown,
    }
}

/// Whether `provenance` may back an unattended readiness claim (module docs).
///
/// # Errors
///
/// `CAPABILITY_UNAVAILABLE` with `controller_dependency` or `dependency_provenance_unknown`.
pub fn unattended_claim(provenance: DependencyProvenance) -> Result<(), OpError> {
    match provenance {
        DependencyProvenance::RunnerManaged | DependencyProvenance::IndependentlyManaged => Ok(()),
        DependencyProvenance::ControllerDependency => Err(OpError::new(
            Code::CapabilityUnavailable,
            "runner work would depend on an agent socket inherited from the controller's session",
        )
        .with_reason(reason::CONTROLLER_DEPENDENCY)),
        DependencyProvenance::Unknown => Err(OpError::new(
            Code::CapabilityUnavailable,
            "the agent's custody is not runner-managed or independently managed: no unattended readiness is claimed",
        )
        .with_reason(reason::DEPENDENCY_PROVENANCE_UNKNOWN)),
    }
}

/// What a path looks like, for the doctor only (never a claim; module docs).
#[must_use]
pub fn path_diagnostic(socket: &Path) -> Option<&'static str> {
    let s = socket.to_string_lossy();
    if s.contains("/ssh-") && s.contains("/agent.") {
        Some("looks like an sshd-forwarded agent socket")
    } else if s.contains("/keyring/") || s.contains("gpg-agent") {
        Some("looks like a desktop keyring or gpg agent socket")
    } else {
        None
    }
}

/// The clean environment of runner work (module docs): `var` reads the launching process's
/// own environment, and only [`PASS_LIST`] is read from it; the result is complete (the
/// pass-list's variables that are set, the launcher-set values from the account database,
/// the fixed `PATH`, and the inventory's agent).
#[must_use]
pub fn clean_environment(
    inventory: &RunnerInventory,
    var: impl Fn(&str) -> Option<OsString>,
) -> Vec<(OsString, OsString)> {
    clean_environment_for(
        inventory,
        var,
        crate::platform::account_entry().ok().as_ref(),
    )
}

/// [`clean_environment`] over a given account entry (`None`: the account database has no
/// usable entry, so no [`LAUNCHER_SET`] variable is set).
#[must_use]
pub fn clean_environment_for(
    inventory: &RunnerInventory,
    var: impl Fn(&str) -> Option<OsString>,
    account: Option<&crate::platform::AccountEntry>,
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = PASS_LIST
        .iter()
        .filter_map(|k| var(k).map(|v| (OsString::from(k), v)))
        .collect();
    if !env.iter().any(|(k, _)| k == "LANG") {
        env.push(("LANG".into(), DEFAULT_LANG.into()));
    }
    if let Some(account) = account {
        let [home, user, logname, shell] = LAUNCHER_SET;
        env.push((home.into(), account.home.clone()));
        env.push((user.into(), account.name.clone()));
        env.push((logname.into(), account.name.clone()));
        env.push((shell.into(), account.shell.clone()));
    }
    env.push(("PATH".into(), CLEAN_PATH.into()));
    if let Some(sock) = inventory.agent_socket() {
        env.push((SSH_AUTH_SOCK.into(), sock.as_os_str().to_owned()));
    }
    env
}

/// A child process for runner work: `program` with `args`, environment cleared and rebuilt by
/// [`clean_environment`], stdin null, no console window (I-24).
pub fn clean_command<I, S>(
    program: &Path,
    args: I,
    inventory: &RunnerInventory,
    var: impl Fn(&str) -> Option<OsString>,
) -> std::process::Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = heimdall_app::no_window!(std::process::Command::new(program));
    command
        .args(args)
        .env_clear()
        .envs(clean_environment(inventory, var))
        .stdin(std::process::Stdio::null());
    command
}

// --- ⟨M06 W5⟩ the launch of runner work ---------------------------------------------------

/// An agent endpoint the binding of the work names for one of its pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundAgent {
    /// The socket path.
    pub socket: PathBuf,
    /// Whether the pair's mechanism is the managed certificate (the runner signer's).
    pub managed: bool,
}

/// Where a reported agent came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentSource {
    /// Named by the binding for a pair.
    Binding,
    /// Inherited by the launching process in `SSH_AUTH_SOCK`.
    Inherited,
}

/// One agent the launch looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentReport {
    /// Where it came from.
    pub source: AgentSource,
    /// Its provenance against the launch's inventory.
    pub provenance: DependencyProvenance,
    /// Whether runner work gets it in `SSH_AUTH_SOCK`.
    pub passed: bool,
    /// What its path looks like (a diagnostic, never a claim).
    pub diagnostic: Option<&'static str>,
}

impl DependencyProvenance {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DependencyProvenance::RunnerManaged => "runner_managed",
            DependencyProvenance::IndependentlyManaged => "independently_managed",
            DependencyProvenance::ControllerDependency => "controller_dependency",
            DependencyProvenance::Unknown => "unknown",
        }
    }
}

/// The launch of one piece of runner work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// The child's complete environment ([`clean_environment`]).
    pub environment: Vec<(OsString, OsString)>,
    /// Every agent looked at, the binding's first.
    pub agents: Vec<AgentReport>,
}

/// `path` with its links resolved when it exists, as written otherwise.
fn resolved(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The inventory of a launch (module docs, "The call site"): the runner signer's endpoints
/// are the managed entries of `bound` under `own_endpoints` (this installation's endpoint
/// directory); `selected` (the one endpoint every pair shares, if any) is the work's signer
/// only when it is one of them.
#[must_use]
pub fn launch_inventory(
    own_endpoints: &Path,
    bound: &[BoundAgent],
    selected: Option<&Path>,
) -> RunnerInventory {
    let own_dir = resolved(own_endpoints);
    let is_own = |b: &BoundAgent| b.managed && resolved(&b.socket).starts_with(&own_dir);
    let own: Vec<&BoundAgent> = bound.iter().filter(|b| is_own(b)).collect();
    RunnerInventory {
        own_signer: selected
            .filter(|s| own.iter().any(|b| b.socket == *s))
            .map(Path::to_path_buf),
        adopted_key_files: Vec::new(),
        verified_signers: own
            .iter()
            .map(|b| VerifiedSigner {
                socket: b.socket.clone(),
                provenance: DependencyProvenance::RunnerManaged,
            })
            .collect(),
    }
}

/// Plan the launch of runner work (module docs, "The call site").
///
/// * `own_endpoints`: this installation's endpoint directory;
/// * `bound`: the agent endpoints the binding names; `selected`: the one every pair shares;
/// * `var`: the launching process's environment;
/// * `unattended`: nobody is present at the launch.
///
/// The environment is [`clean_environment`] over [`launch_inventory`]: nothing else of the
/// launching process's environment reaches the work, so an agent it inherited never does.
/// Each agent of the binding, then the inherited one when the binding does not name it, is
/// reported with its provenance.
///
/// # Errors
///
/// Unattended, with a binding that names an agent that is neither runner-managed nor
/// independently managed: [`unattended_claim`]'s refusal (`controller_dependency` before
/// `dependency_provenance_unknown`). Nothing is launched.
pub fn plan_launch(
    own_endpoints: &Path,
    bound: &[BoundAgent],
    selected: Option<&Path>,
    var: impl Fn(&str) -> Option<OsString>,
    unattended: bool,
) -> Result<LaunchPlan, OpError> {
    let inventory = launch_inventory(own_endpoints, bound, selected);
    let inherited = inherited_agent(&var);
    let passed = inventory.agent_socket().map(Path::to_path_buf);
    let mut agents: Vec<AgentReport> = Vec::new();
    let mut seen: Vec<&Path> = Vec::new();
    let mut refusal: Option<DependencyProvenance> = None;
    for b in bound {
        if seen.contains(&b.socket.as_path()) {
            continue;
        }
        seen.push(&b.socket);
        // An agent the binding names that is also the one this process inherited came the
        // way the inherited one did.
        let origin = inherited
            .as_ref()
            .filter(|i| i.socket == b.socket)
            .map_or(AgentOrigin::Configured, |i| i.origin);
        let provenance = classify_agent(
            &AgentCandidate {
                socket: b.socket.clone(),
                origin,
            },
            &inventory,
        );
        if unattended_claim(provenance).is_err()
            && refusal != Some(DependencyProvenance::ControllerDependency)
        {
            refusal = Some(match (refusal, provenance) {
                (_, DependencyProvenance::ControllerDependency) => provenance,
                (Some(first), _) => first,
                (None, _) => provenance,
            });
        }
        agents.push(AgentReport {
            source: AgentSource::Binding,
            provenance,
            passed: passed.as_deref() == Some(b.socket.as_path()),
            diagnostic: path_diagnostic(&b.socket),
        });
    }
    if unattended && let Some(provenance) = refusal {
        unattended_claim(provenance)?;
    }
    if let Some(candidate) = inherited.filter(|i| !seen.contains(&i.socket.as_path())) {
        agents.push(AgentReport {
            source: AgentSource::Inherited,
            provenance: classify_agent(&candidate, &inventory),
            // Only an inventoried signer is ever passed, and the binding names those.
            passed: false,
            diagnostic: path_diagnostic(&candidate.socket),
        });
    }
    Ok(LaunchPlan {
        environment: clean_environment(&inventory, var),
        agents,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(*v)))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn only_inventoried_signers_are_claimed() {
        let inventory = RunnerInventory {
            own_signer: Some("/run/user/1000/heimdall/b1.sock".into()),
            adopted_key_files: vec!["/home/runner/.ssh/id_ed25519".into()],
            verified_signers: vec![VerifiedSigner {
                socket: "/run/user/1000/tpm-agent.sock".into(),
                provenance: DependencyProvenance::IndependentlyManaged,
            }],
        };
        let c = |p: &str, origin| AgentCandidate {
            socket: p.into(),
            origin,
        };
        assert_eq!(
            classify_agent(
                &c("/run/user/1000/heimdall/b1.sock", AgentOrigin::Configured),
                &inventory
            ),
            DependencyProvenance::RunnerManaged
        );
        assert_eq!(
            classify_agent(
                &c("/run/user/1000/tpm-agent.sock", AgentOrigin::InheritedLocal),
                &inventory
            ),
            DependencyProvenance::IndependentlyManaged
        );
        // Inherited from the management session: the controller's.
        assert_eq!(
            classify_agent(
                &c(
                    "/tmp/ssh-XXXX/agent.123",
                    AgentOrigin::InheritedFromSshSession
                ),
                &inventory
            ),
            DependencyProvenance::ControllerDependency
        );
        // An ordinary path is unknown whatever it looks like.
        assert_eq!(
            classify_agent(
                &c("/home/runner/.ssh/agent.sock", AgentOrigin::Configured),
                &inventory
            ),
            DependencyProvenance::Unknown
        );
        assert!(unattended_claim(DependencyProvenance::RunnerManaged).is_ok());
        assert!(unattended_claim(DependencyProvenance::IndependentlyManaged).is_ok());
        let e = unattended_claim(DependencyProvenance::ControllerDependency).unwrap_err();
        assert_eq!(e.code, Code::CapabilityUnavailable);
        assert_eq!(e.reason.as_deref(), Some(reason::CONTROLLER_DEPENDENCY));
        let e = unattended_claim(DependencyProvenance::Unknown).unwrap_err();
        assert_eq!(
            e.reason.as_deref(),
            Some(reason::DEPENDENCY_PROVENANCE_UNKNOWN)
        );
    }

    #[test]
    fn the_inherited_agent_names_its_origin() {
        let from_ssh = inherited_agent(env(&[
            ("SSH_AUTH_SOCK", "/tmp/ssh-abc/agent.7"),
            ("SSH_CONNECTION", "192.0.2.1 50000 192.0.2.2 22"),
        ]))
        .unwrap();
        assert_eq!(from_ssh.origin, AgentOrigin::InheritedFromSshSession);
        let local =
            inherited_agent(env(&[("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh")])).unwrap();
        assert_eq!(local.origin, AgentOrigin::InheritedLocal);
        assert_eq!(inherited_agent(env(&[("SSH_AUTH_SOCK", "")])), None);
        assert_eq!(inherited_agent(env(&[])), None);
        assert!(path_diagnostic(&from_ssh.socket).is_some());
        assert!(path_diagnostic(Path::new("/home/runner/.ssh/agent.sock")).is_none());
    }

    #[test]
    fn the_clean_environment_holds_only_the_inventory() {
        let parent = env(&[
            ("HOME", "/home/runner"),
            ("USER", "runner"),
            ("SSH_AUTH_SOCK", "/tmp/ssh-abc/agent.7"),
            ("SSH_CONNECTION", "192.0.2.1 50000 192.0.2.2 22"),
            ("PATH", "/home/runner/bin:/usr/bin"),
            ("LD_PRELOAD", "/tmp/x.so"),
        ]);
        let none = clean_environment_for(&RunnerInventory::default(), &parent, None);
        let keys: Vec<_> = none
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        // HOME, USER and the parent's PATH are not on the pass-list; with no account entry
        // nothing stands in for them.
        assert_eq!(keys, ["LANG", "PATH"]);
        assert!(none.iter().any(|(k, v)| k == "PATH" && v == CLEAN_PATH));
        assert!(none.iter().any(|(k, v)| k == "LANG" && v == DEFAULT_LANG));
        // With an entry, the four launcher-set values are the entry's, never the parent's.
        let entry = crate::platform::AccountEntry {
            name: "fixture".into(),
            home: "/fixture/home".into(),
            shell: "/fixture/sh".into(),
        };
        let set = clean_environment_for(&RunnerInventory::default(), &parent, Some(&entry));
        assert_eq!(
            set,
            [
                ("LANG", DEFAULT_LANG),
                ("HOME", "/fixture/home"),
                ("USER", "fixture"),
                ("LOGNAME", "fixture"),
                ("SHELL", "/fixture/sh"),
                ("PATH", CLEAN_PATH),
            ]
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        );
        let own = RunnerInventory {
            own_signer: Some("/run/user/1000/heimdall/b1.sock".into()),
            ..RunnerInventory::default()
        };
        let with = clean_environment_for(&own, &parent, None);
        assert!(
            with.iter()
                .any(|(k, v)| k == SSH_AUTH_SOCK && v == "/run/user/1000/heimdall/b1.sock")
        );
        assert!(
            !with
                .iter()
                .any(|(k, _)| k == "SSH_CONNECTION" || k == "LD_PRELOAD")
        );
    }

    /// ⟨M06 W5; ADR-0012 §4 item 5 "The declared pass-list" ⟨2026-11-22⟩⟩ The pass-list is
    /// exactly these eight names (a change here is a change to the ADR's list), and
    /// `SSH_AUTH_SOCK` is not one of them.
    #[test]
    fn the_declared_pass_list_is_exactly_the_ruled_set() {
        assert_eq!(
            PASS_LIST,
            [
                "HEIMDALL_HOME",
                "XDG_CONFIG_HOME",
                "XDG_STATE_HOME",
                "XDG_RUNTIME_DIR",
                "TERM",
                "TZ",
                "LANG",
                "LC_ALL",
            ]
        );
        assert!(!PASS_LIST.contains(&SSH_AUTH_SOCK));
        // The launcher-set names are not on it either: they never come from the parent.
        assert!(LAUNCHER_SET.iter().all(|k| !PASS_LIST.contains(k)));
        assert_eq!(LAUNCHER_SET, ["HOME", "USER", "LOGNAME", "SHELL"]);
        // Every listed variable is copied verbatim (a parent's LANG passes); a parent that
        // sets none gives only the default LANG and PATH.
        let all: Vec<(&str, String)> = PASS_LIST
            .iter()
            .map(|k| (*k, format!("value of {k}")))
            .collect();
        let pairs: Vec<(&str, &str)> = all.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let full = clean_environment_for(&RunnerInventory::default(), env(&pairs), None);
        let mut expected: Vec<(OsString, OsString)> = all
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect();
        expected.push(("PATH".into(), CLEAN_PATH.into()));
        assert_eq!(full, expected);
        assert_eq!(
            clean_environment_for(&RunnerInventory::default(), env(&[]), None),
            [("LANG", DEFAULT_LANG), ("PATH", CLEAN_PATH)]
                .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        );
    }

    /// ⟨M06 W5⟩ A **real child process** started by the clean launch from a parent
    /// environment that holds every pass-list variable, this test process's whole own
    /// environment, a forwarded agent and other session leftovers: the child's environment
    /// is exactly the pass-list (verbatim), the fixed `PATH` and the four launcher-set
    /// values; nothing else of the parent reaches it, and `SSH_AUTH_SOCK` in particular
    /// never does. With an inventoried signer the child's `SSH_AUTH_SOCK` is that signer's,
    /// never the parent's.
    ///
    /// ⟨"Launcher-set values" ⟨2026-11-22⟩⟩ `HOME`, `USER`, `LOGNAME` and `SHELL` are the
    /// account database's although the parent sets each to something else: the name is
    /// compared with what `id -un` prints (an independent read of the same database), the
    /// home and shell with the entry of this process's uid. With no `LANG` in the parent
    /// the child has `LANG=C.UTF-8`.
    #[cfg(unix)]
    #[test]
    fn a_real_child_gets_exactly_the_pass_list_and_never_the_parents_agent() {
        const FORWARDED: &str = "/tmp/ssh-hmfixture/agent.4242";
        let mut parent: HashMap<String, OsString> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v)))
            .collect();
        for k in PASS_LIST {
            parent.insert(k.to_owned(), format!("pass-{k}").into());
        }
        for (k, v) in [
            (SSH_AUTH_SOCK, FORWARDED),
            ("SSH_CONNECTION", "192.0.2.1 50000 192.0.2.2 22"),
            ("SSH_CLIENT", "192.0.2.1 50000 22"),
            ("HOME", "/home/hm-fixture"),
            ("USER", "hm-fixture"),
            ("LOGNAME", "hm-fixture"),
            ("SHELL", "/home/hm-fixture/bin/not-a-shell"),
            ("PATH", "/home/hm-fixture/bin:/usr/bin"),
            ("LC_CTYPE", "C"),
            ("LD_PRELOAD", "/tmp/x.so"),
            ("GIT_SSH_COMMAND", "ssh -A"),
            ("HEIMDALL_TEST_SSH_HOME", "/tmp/hm-fixture"),
            ("HM_SESSION_MARK", "left-behind"),
        ] {
            parent.insert(k.to_owned(), v.into());
        }
        assert!(parent.len() > PASS_LIST.len() + 10);
        let account = crate::platform::account_entry().unwrap();
        let text = |v: &OsString| v.to_str().unwrap().to_owned();
        let id = std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .unwrap();
        assert!(id.status.success());
        assert_eq!(
            String::from_utf8(id.stdout).unwrap().trim(),
            text(&account.name)
        );
        assert_ne!(text(&account.name), "hm-fixture");
        assert_ne!(text(&account.home), "/home/hm-fixture");
        let from_account = [
            ("HOME".to_owned(), text(&account.home)),
            ("USER".to_owned(), text(&account.name)),
            ("LOGNAME".to_owned(), text(&account.name)),
            ("SHELL".to_owned(), text(&account.shell)),
        ];
        let run_in = |parent: &HashMap<String, OsString>,
                      inventory: &RunnerInventory|
         -> Vec<(String, String)> {
            let out = clean_command(
                Path::new("/usr/bin/env"),
                std::iter::empty::<&str>(),
                inventory,
                |k: &str| parent.get(k).cloned(),
            )
            .output()
            .unwrap();
            assert!(out.status.success());
            let mut seen: Vec<(String, String)> = String::from_utf8(out.stdout)
                .unwrap()
                .lines()
                .map(|l| {
                    let (k, v) = l.split_once('=').unwrap();
                    (k.to_owned(), v.to_owned())
                })
                // macOS's `env` is started through a launcher that may add this one itself.
                .filter(|(k, _)| k != "__CF_USER_TEXT_ENCODING")
                .collect();
            seen.sort();
            seen
        };
        let run = |inventory: &RunnerInventory| run_in(&parent, inventory);
        let mut expected: Vec<(String, String)> = PASS_LIST
            .iter()
            .map(|k| ((*k).to_owned(), format!("pass-{k}")))
            .collect();
        expected.push(("PATH".to_owned(), CLEAN_PATH.to_owned()));
        expected.extend(from_account.iter().cloned());
        expected.sort();
        let none = run(&RunnerInventory::default());
        assert_eq!(none, expected);
        assert!(
            !none.iter().any(|(_, v)| v.contains("hm-fixture")),
            "a parent's HOME, USER, LOGNAME or SHELL reached the child"
        );
        // No LANG in the parent: the launcher sets the default; nothing else changes.
        let mut no_lang = parent.clone();
        no_lang.remove("LANG");
        let mut expected_default: Vec<(String, String)> = expected
            .iter()
            .filter(|(k, _)| k != "LANG")
            .cloned()
            .collect();
        expected_default.push(("LANG".to_owned(), DEFAULT_LANG.to_owned()));
        expected_default.sort();
        assert_eq!(
            run_in(&no_lang, &RunnerInventory::default()),
            expected_default
        );
        assert!(
            !none
                .iter()
                .any(|(k, v)| k == SSH_AUTH_SOCK || v.contains("ssh-hmfixture")),
            "the parent's agent reached the child"
        );
        let own = RunnerInventory {
            own_signer: Some("/run/user/1000/heimdall/b/0123456789abcdef/agent.sock".into()),
            ..RunnerInventory::default()
        };
        let with = run(&own);
        expected.push((
            SSH_AUTH_SOCK.to_owned(),
            "/run/user/1000/heimdall/b/0123456789abcdef/agent.sock".to_owned(),
        ));
        expected.sort();
        assert_eq!(with, expected);
        assert!(!with.iter().any(|(_, v)| v.contains("ssh-hmfixture")));
    }

    fn value<'a>(env: &'a [(OsString, OsString)], key: &str) -> Option<&'a OsString> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// ⟨M06 W5⟩ The launch of runner work: the runner signer's endpoint (a managed pair's,
    /// under this installation's endpoint directory) is the only agent passed; a forwarded
    /// agent the launching process inherited is reported `controller_dependency`, an
    /// inherited one at an ordinary path `unknown`, and neither reaches the work.
    #[test]
    fn a_launch_passes_only_the_runner_signer_and_reports_the_inherited_agent() {
        let own_dir = Path::new("/run/user/1000/heimdall");
        let own = PathBuf::from("/run/user/1000/heimdall/b1.sock");
        let bound = [BoundAgent {
            socket: own.clone(),
            managed: true,
        }];
        let forwarded = env(&[
            ("HOME", "/home/runner"),
            ("HEIMDALL_HOME", "/home/runner/hm"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("SSH_AUTH_SOCK", "/tmp/ssh-abc/agent.7"),
            ("SSH_CONNECTION", "192.0.2.1 50000 192.0.2.2 22"),
            ("TERM", "xterm"),
        ]);
        for unattended in [false, true] {
            let plan = plan_launch(own_dir, &bound, Some(&own), &forwarded, unattended).unwrap();
            assert_eq!(
                value(&plan.environment, SSH_AUTH_SOCK),
                Some(&own.clone().into())
            );
            assert_eq!(
                value(&plan.environment, "HEIMDALL_HOME"),
                Some(&"/home/runner/hm".into())
            );
            assert_eq!(
                value(&plan.environment, "XDG_RUNTIME_DIR"),
                Some(&"/run/user/1000".into())
            );
            assert!(value(&plan.environment, "SSH_CONNECTION").is_none());
            // HOME is the account database's or absent, never the parent's.
            assert_ne!(
                value(&plan.environment, "HOME"),
                Some(&"/home/runner".into())
            );
            assert_eq!(value(&plan.environment, "TERM"), Some(&"xterm".into()));
            assert!(
                !plan
                    .environment
                    .iter()
                    .any(|(_, v)| v.to_string_lossy().contains("/tmp/ssh-abc")),
                "the forwarded socket is nowhere in the work's environment"
            );
            assert_eq!(
                plan.agents,
                [
                    AgentReport {
                        source: AgentSource::Binding,
                        provenance: DependencyProvenance::RunnerManaged,
                        passed: true,
                        diagnostic: None,
                    },
                    AgentReport {
                        source: AgentSource::Inherited,
                        provenance: DependencyProvenance::ControllerDependency,
                        passed: false,
                        diagnostic: Some("looks like an sshd-forwarded agent socket"),
                    },
                ]
            );
        }
        // The same socket at an ordinary path, with no SSH session beside it: unknown.
        let ordinary = env(&[("SSH_AUTH_SOCK", "/home/runner/.ssh/agent.sock")]);
        let plan = plan_launch(own_dir, &bound, Some(&own), &ordinary, true).unwrap();
        assert_eq!(plan.agents[1].provenance, DependencyProvenance::Unknown);
        assert_eq!(plan.agents[1].provenance.as_str(), "unknown");
        assert!(!plan.agents[1].passed);
        assert_eq!(value(&plan.environment, SSH_AUTH_SOCK), Some(&own.into()));
        // No binding agent and an inherited one: the work gets no agent at all.
        let plan = plan_launch(own_dir, &[], None, &ordinary, true).unwrap();
        assert!(value(&plan.environment, SSH_AUTH_SOCK).is_none());
        assert_eq!(plan.agents.len(), 1);
        assert_eq!(plan.agents[0].source, AgentSource::Inherited);
    }

    /// ⟨M06 W5; A24⟩ A binding that depends on an agent outside the inventory: unattended,
    /// the launch is refused (`controller_dependency` for the inherited SSH session's
    /// socket, `dependency_provenance_unknown` for any other, whatever its path or its
    /// mechanism's name); attended, it is reported and still never passed.
    #[test]
    fn an_unattended_launch_on_an_agent_outside_the_inventory_is_refused() {
        let own_dir = Path::new("/run/user/1000/heimdall");
        let ordinary = PathBuf::from("/home/runner/.ssh/agent.sock");
        let none = env(&[("HOME", "/home/runner")]);
        let fixed = [BoundAgent {
            socket: ordinary.clone(),
            managed: false,
        }];
        let e = plan_launch(own_dir, &fixed, Some(&ordinary), &none, true).unwrap_err();
        assert_eq!(e.code, Code::CapabilityUnavailable);
        assert_eq!(
            e.reason.as_deref(),
            Some(reason::DEPENDENCY_PROVENANCE_UNKNOWN)
        );
        let attended = plan_launch(own_dir, &fixed, Some(&ordinary), &none, false).unwrap();
        assert_eq!(attended.agents[0].provenance, DependencyProvenance::Unknown);
        assert!(!attended.agents[0].passed);
        assert!(value(&attended.environment, SSH_AUTH_SOCK).is_none());
        // A managed pair whose endpoint is not under this installation's directory is not
        // the runner signer's: the mechanism's name alone claims nothing.
        let elsewhere = [BoundAgent {
            socket: ordinary.clone(),
            managed: true,
        }];
        let e = plan_launch(own_dir, &elsewhere, Some(&ordinary), &none, true).unwrap_err();
        assert_eq!(
            e.reason.as_deref(),
            Some(reason::DEPENDENCY_PROVENANCE_UNKNOWN)
        );
        // An unmanaged pair under the directory is not the runner signer's either.
        let squatter = [BoundAgent {
            socket: "/run/user/1000/heimdall/x.sock".into(),
            managed: false,
        }];
        assert!(plan_launch(own_dir, &squatter, None, &none, true).is_err());
        // The binding names the very socket this process inherited from an SSH session.
        let session = env(&[
            ("SSH_AUTH_SOCK", "/home/runner/.ssh/agent.sock"),
            ("SSH_CLIENT", "192.0.2.1 50000 22"),
        ]);
        let own = BoundAgent {
            socket: "/run/user/1000/heimdall/b1.sock".into(),
            managed: true,
        };
        let both = [own, fixed[0].clone()];
        let e = plan_launch(own_dir, &both, None, &session, true).unwrap_err();
        assert_eq!(e.reason.as_deref(), Some(reason::CONTROLLER_DEPENDENCY));
        let attended = plan_launch(own_dir, &both, None, &session, false).unwrap();
        assert_eq!(
            attended
                .agents
                .iter()
                .map(|a| (a.source, a.provenance, a.passed))
                .collect::<Vec<_>>(),
            [
                (
                    AgentSource::Binding,
                    DependencyProvenance::RunnerManaged,
                    false
                ),
                (
                    AgentSource::Binding,
                    DependencyProvenance::ControllerDependency,
                    false
                ),
            ]
        );
        assert!(value(&attended.environment, SSH_AUTH_SOCK).is_none());
    }
}
