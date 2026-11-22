//! ⟨M06 U3⟩ Dependencies by construction (ADR-0012 §4.5, §4.6; A24): runner work starts from
//! a clean environment holding only an explicit inventory of runner-owned sources, and an
//! agent outside that inventory is never claimed for unattended readiness.
//!
//! * **The inventory** ([`RunnerInventory`]): the runner signer's own endpoint, runner-local
//!   key files adopted as existing access, and local signers verified as independently managed
//!   (each with its provenance).
//! * **Clean launch** ([`clean_environment`], [`clean_command`]): the child's environment is
//!   cleared and rebuilt from a fixed allowlist (`HOME`, `USER`, `LOGNAME`, `LANG`, a fixed
//!   `PATH`) plus `SSH_AUTH_SOCK` **only** when the inventory names a signer for it. Nothing is
//!   inherited from the process that started the runner, so a socket the management session
//!   brought along (an inherited controller socket) never reaches runner work.
//! * **Provenance** ([`classify_agent`]): the runner's own signer is `runner_managed`; an
//!   inventoried verified signer is `independently_managed`; an agent the runner's own process
//!   inherited from an SSH session is a `controller_dependency`; **any other agent is
//!   `unknown`**, including an ordinary local path that may relay to the controller. A path's
//!   shape is never evidence: [`path_diagnostic`] names what a path looks like for the doctor
//!   and nothing else.
//! * **The claim** ([`unattended_claim`]): only `runner_managed` and `independently_managed`
//!   may back unattended readiness; the others are refused `CAPABILITY_UNAVAILABLE` with
//!   `controller_dependency` or `dependency_provenance_unknown`.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use heimdall_app::OpError;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::reason;

/// The `PATH` runner work starts with (system directories only; never inherited).
pub const CLEAN_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The `LANG` runner work starts with.
pub const CLEAN_LANG: &str = "C.UTF-8";

/// Inherited variables copied verbatim when present (identity of the runner account only).
pub const INHERITED_IDENTITY: [&str; 3] = ["HOME", "USER", "LOGNAME"];

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

/// The clean environment of runner work (module docs): `var` reads the runner process's own
/// environment (only the identity variables are copied); the result is complete.
#[must_use]
pub fn clean_environment(
    inventory: &RunnerInventory,
    var: impl Fn(&str) -> Option<OsString>,
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = INHERITED_IDENTITY
        .iter()
        .filter_map(|k| var(k).map(|v| (OsString::from(k), v)))
        .collect();
    env.push(("PATH".into(), CLEAN_PATH.into()));
    env.push(("LANG".into(), CLEAN_LANG.into()));
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
        let none = clean_environment(&RunnerInventory::default(), &parent);
        let keys: Vec<_> = none
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(keys, ["HOME", "USER", "PATH", "LANG"]);
        assert!(none.iter().any(|(k, v)| k == "PATH" && v == CLEAN_PATH));
        let own = RunnerInventory {
            own_signer: Some("/run/user/1000/heimdall/b1.sock".into()),
            ..RunnerInventory::default()
        };
        let with = clean_environment(&own, &parent);
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
}
