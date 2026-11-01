//! Passive provider detection (m02-plan U6; ADR-0007 §6, §7).
//!
//! Detection opens nothing and contacts nothing. On Unix it stats the socket path
//! (`stat`, following a symlink as `connect` would): a socket owned by our UID is
//! present, any other file type is not an endpoint, and a socket owned by another
//! UID is refused (`agent_endpoint_foreign_owner`) without ever being connected to. On
//! Windows it lists the names under `\\.\pipe\` (`std::fs::read_dir`) without opening
//! any pipe; the pipe's owner is checked only by the explicit `agent` probe.
//!
//! Endpoints come only from `SSH_AUTH_SOCK` (read from an [`Env`] snapshot, never from
//! the live process environment) and from `IdentityAgent` references the static
//! evaluation found (`heimdall_localenv::agents::detect_agents`, U3). No 1Password
//! socket or pipe path is hardcoded (ADR-0007 §7, §12.14 item 8): the pinned vendor
//! excerpts are not available, so a 1Password endpoint is known only through those two
//! references or the catalog identity that names it.
//!
//! What passive detection can establish (ADR-0007 §7 "Provider states"): `unavailable`
//! (no usable endpoint) and `unknown`. `available` and `locked` need the explicit
//! `agent` level ([`crate::state::status_from_listing`]).

use std::path::{Path, PathBuf};

use heimdall_contract::Timestamp;
use heimdall_contract::provider::{
    EndpointKind, EndpointRef, EvidenceBasis, ProbeLevel, ProviderAvailability, ProviderKind,
    ProviderStatus,
};
use heimdall_ipc::agent_client::AgentLocator;
use heimdall_localenv::agents::{AgentEndpoint, EndpointLocator, Presence};
use heimdall_localenv::env::{Env, Platform};

/// The environment variable that names the default agent.
pub const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

/// Most `\\.\pipe\` names read before giving up (`unknown`): the listing is bounded.
#[cfg(windows)]
const MAX_PIPE_NAMES: usize = 65_536;

/// What a passive look at an endpoint found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointPresence {
    /// A socket owned by our UID, or a pipe name that is listed.
    Present,
    /// Nothing at the path or name.
    Absent,
    /// A socket owned by another UID: never connected to.
    ForeignOwner,
    /// Something that is not an agent endpoint on this platform (a regular file, a
    /// relative path, a pipe name on Unix, a socket path on Windows).
    NotAnEndpoint,
    /// It could not be checked.
    Unknown,
}

impl EndpointPresence {
    /// The `heimdall_localenv` presence (U3's detection) in these terms.
    #[must_use]
    pub fn from_detected(presence: Presence) -> Self {
        match presence {
            Presence::Present => EndpointPresence::Present,
            Presence::Absent => EndpointPresence::Absent,
            Presence::ForeignOwner => EndpointPresence::ForeignOwner,
            Presence::Unknown => EndpointPresence::Unknown,
        }
    }

    /// A short nonsecret description, used in adapter errors.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            EndpointPresence::Present => "agent endpoint present",
            EndpointPresence::Absent => "agent endpoint absent",
            EndpointPresence::ForeignOwner => "agent endpoint owned by another user",
            EndpointPresence::NotAnEndpoint => "agent endpoint is not a socket or pipe",
            EndpointPresence::Unknown => "agent endpoint could not be checked",
        }
    }
}

/// Look at `endpoint` passively: stat on Unix, a `\\.\pipe\` listing on Windows.
#[must_use]
pub fn observe_endpoint(endpoint: &EndpointRef) -> EndpointPresence {
    match endpoint.kind {
        EndpointKind::UnixSocket => observe_socket(Path::new(&endpoint.locator)),
        EndpointKind::NamedPipe => observe_pipe(&endpoint.locator),
        // A transport this build does not know: claim nothing.
        _ => EndpointPresence::Unknown,
    }
}

#[cfg(unix)]
fn observe_socket(path: &Path) -> EndpointPresence {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    // A relative path would resolve against the runtime's directory, not the
    // caller's: refused.
    if !path.is_absolute() {
        return EndpointPresence::NotAnEndpoint;
    }
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => EndpointPresence::Absent,
        Err(_) => EndpointPresence::Unknown,
        Ok(meta) if !meta.file_type().is_socket() => EndpointPresence::NotAnEndpoint,
        Ok(meta) if meta.uid() != heimdall_ipc::unix::current_uid() => {
            EndpointPresence::ForeignOwner
        }
        Ok(_) => EndpointPresence::Present,
    }
}

#[cfg(not(unix))]
fn observe_socket(_path: &Path) -> EndpointPresence {
    // Unix-domain agents are not an M02 transport on this platform.
    EndpointPresence::NotAnEndpoint
}

#[cfg(windows)]
fn observe_pipe(locator: &str) -> EndpointPresence {
    let Some(name) = heimdall_ipc::agent_client::pipe_name(locator) else {
        return EndpointPresence::NotAnEndpoint;
    };
    let Ok(entries) = std::fs::read_dir(r"\\.\pipe\") else {
        return EndpointPresence::Unknown;
    };
    for (seen, entry) in entries.enumerate() {
        if seen >= MAX_PIPE_NAMES {
            return EndpointPresence::Unknown;
        }
        let Ok(entry) = entry else {
            return EndpointPresence::Unknown;
        };
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
        {
            return EndpointPresence::Present;
        }
    }
    EndpointPresence::Absent
}

#[cfg(not(windows))]
fn observe_pipe(_locator: &str) -> EndpointPresence {
    EndpointPresence::NotAnEndpoint
}

/// The endpoint `SSH_AUTH_SOCK` names in `env`, when it names one. A value that is
/// empty or not Unicode names none. On Windows a value in the pipe namespace is a
/// named pipe; any other value is a socket path (which this build does not reach on
/// Windows).
#[must_use]
pub fn ssh_auth_sock(env: &Env, platform: Platform) -> Option<EndpointRef> {
    let value = env.get(SSH_AUTH_SOCK)?.to_str()?;
    if value.is_empty() {
        return None;
    }
    let pipe = platform == Platform::Windows && is_pipe_path(value);
    Some(EndpointRef {
        kind: if pipe {
            EndpointKind::NamedPipe
        } else {
            EndpointKind::UnixSocket
        },
        locator: value.to_owned(),
    })
}

fn is_pipe_path(value: &str) -> bool {
    [r"\\.\pipe\", "//./pipe/", r"\\?\pipe\"].iter().any(|p| {
        value.len() > p.len()
            && value.is_char_boundary(p.len())
            && value[..p.len()].eq_ignore_ascii_case(p)
    })
}

/// The agent client's locator for `endpoint`; `None` for a transport this build
/// does not know.
#[must_use]
pub fn locator(endpoint: &EndpointRef) -> Option<AgentLocator> {
    match endpoint.kind {
        EndpointKind::UnixSocket => {
            Some(AgentLocator::UnixSocket(PathBuf::from(&endpoint.locator)))
        }
        EndpointKind::NamedPipe => Some(AgentLocator::NamedPipe(endpoint.locator.clone())),
        _ => None,
    }
}

/// An endpoint reference for a locator U3's detection produced; `None` for a socket
/// path that is not Unicode (an [`EndpointRef`] carries text).
#[must_use]
pub fn endpoint_ref(locator: &EndpointLocator) -> Option<EndpointRef> {
    match locator {
        EndpointLocator::UnixSocket(path) => Some(EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: path.to_str()?.to_owned(),
        }),
        EndpointLocator::NamedPipe(name) => Some(EndpointRef {
            kind: EndpointKind::NamedPipe,
            locator: name.clone(),
        }),
    }
}

/// The passive status of `provider` given what was seen at its endpoint (`None`: no
/// endpoint is known at all). Only `unavailable` and `unknown` availability can come
/// from here; interaction is the provider's documented default
/// ([`crate::state::documented_interaction`]).
#[must_use]
pub fn passive_status(
    provider: ProviderKind,
    presence: Option<EndpointPresence>,
    now: Timestamp,
) -> ProviderStatus {
    let (interaction, documented) = crate::state::documented_interaction(provider);
    let (availability, basis) = match presence {
        Some(EndpointPresence::Present) => (ProviderAvailability::Unknown, documented),
        Some(EndpointPresence::Unknown) => (ProviderAvailability::Unknown, EvidenceBasis::Inferred),
        None
        | Some(
            EndpointPresence::Absent
            | EndpointPresence::ForeignOwner
            | EndpointPresence::NotAnEndpoint,
        ) => (ProviderAvailability::Unavailable, EvidenceBasis::Observed),
    };
    ProviderStatus {
        provider,
        availability,
        interaction,
        observed_level: ProbeLevel::Static,
        observed_at: now,
        basis,
    }
}

/// The passive status of every endpoint U3's detection found, in its order. The
/// provider is the one detection named (`unknown` for the Windows system pipe, F18).
#[must_use]
pub fn statuses(endpoints: &[AgentEndpoint], now: Timestamp) -> Vec<ProviderStatus> {
    endpoints
        .iter()
        .map(|e| {
            passive_status(
                e.provider,
                Some(EndpointPresence::from_detected(e.presence)),
                now,
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ssh_auth_sock_comes_from_the_snapshot_only() {
        let env = Env::from_vars([(SSH_AUTH_SOCK, "/scratch/agent.sock")]);
        assert_eq!(
            ssh_auth_sock(&env, Platform::Linux),
            Some(EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: "/scratch/agent.sock".into(),
            })
        );
        assert_eq!(ssh_auth_sock(&Env::default(), Platform::MacOs), None);
        let empty = Env::from_vars([(SSH_AUTH_SOCK, "")]);
        assert_eq!(ssh_auth_sock(&empty, Platform::Linux), None);
        let pipe = Env::from_vars([(SSH_AUTH_SOCK, r"\\.\pipe\openssh-ssh-agent")]);
        assert_eq!(
            ssh_auth_sock(&pipe, Platform::Windows).map(|e| e.kind),
            Some(EndpointKind::NamedPipe)
        );
    }

    #[test]
    fn passive_detection_never_claims_available_or_locked() {
        let now = Timestamp::UNIX_EPOCH;
        for provider in [ProviderKind::NativeAgent, ProviderKind::OnePassword] {
            for presence in [
                None,
                Some(EndpointPresence::Present),
                Some(EndpointPresence::Absent),
                Some(EndpointPresence::ForeignOwner),
                Some(EndpointPresence::NotAnEndpoint),
                Some(EndpointPresence::Unknown),
            ] {
                let s = passive_status(provider, presence, now);
                assert!(
                    matches!(
                        s.availability,
                        ProviderAvailability::Unknown | ProviderAvailability::Unavailable
                    ),
                    "{provider:?} {presence:?}"
                );
                assert_eq!(s.observed_level, ProbeLevel::Static);
            }
        }
    }

    #[test]
    fn detected_endpoints_map_to_passive_statuses() {
        use heimdall_contract::provider::InteractionKind;
        use heimdall_localenv::agents::EndpointSource;
        let now = Timestamp::UNIX_EPOCH;
        let found = [
            AgentEndpoint {
                provider: ProviderKind::OnePassword,
                locator: EndpointLocator::UnixSocket(PathBuf::from("/scratch/op.sock")),
                presence: Presence::Present,
                source: EndpointSource::SshAuthSock,
            },
            AgentEndpoint {
                provider: ProviderKind::Unknown,
                locator: EndpointLocator::NamedPipe(r"\\.\pipe\openssh-ssh-agent".into()),
                presence: Presence::ForeignOwner,
                source: EndpointSource::WindowsSystemPipe,
            },
        ];
        let s = statuses(&found, now);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].provider, ProviderKind::OnePassword);
        assert_eq!(s[0].availability, ProviderAvailability::Unknown);
        assert_eq!(s[0].interaction, InteractionKind::ProviderApproval);
        assert_eq!(s[0].basis, EvidenceBasis::Documented);
        assert_eq!(s[1].provider, ProviderKind::Unknown);
        assert_eq!(s[1].availability, ProviderAvailability::Unavailable);
        assert_eq!(s[1].interaction, InteractionKind::Unknown);
        assert_eq!(
            endpoint_ref(&found[1].locator).map(|e| e.kind),
            Some(EndpointKind::NamedPipe)
        );
        assert_eq!(
            endpoint_ref(&found[0].locator).and_then(|e| locator(&e)),
            Some(AgentLocator::UnixSocket(PathBuf::from("/scratch/op.sock")))
        );
    }

    #[cfg(unix)]
    #[test]
    fn relative_socket_paths_and_pipe_names_are_not_endpoints_on_unix() {
        let rel = EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: "agent.sock".into(),
        };
        assert_eq!(observe_endpoint(&rel), EndpointPresence::NotAnEndpoint);
        let pipe = EndpointRef {
            kind: EndpointKind::NamedPipe,
            locator: "openssh-ssh-agent".into(),
        };
        assert_eq!(observe_endpoint(&pipe), EndpointPresence::NotAnEndpoint);
    }
}
