//! Endpoint kinds, locations and peer verification (spec §13.2; ADR-0006 §2.1).

use std::path::{Path, PathBuf};

/// The two local endpoints. They never share a path, a listener, or a protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    /// Management: policy, preparation, inspection, lifecycle.
    Control,
    /// Already-authorized credential operations only (SSH agent protocol).
    Signing,
}

impl EndpointKind {
    /// File-name component (Unix) or pipe-name suffix (Windows).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            EndpointKind::Control => "control",
            EndpointKind::Signing => "signing",
        }
    }

    /// Frame limit for this endpoint.
    #[must_use]
    pub fn max_frame_bytes(self) -> usize {
        match self {
            EndpointKind::Control => heimdall_contract::ipc::MAX_CONTROL_FRAME_BYTES,
            EndpointKind::Signing => heimdall_contract::ipc::MAX_SIGNING_FRAME_BYTES,
        }
    }
}

/// Resolved endpoint locations for one runtime instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPaths {
    /// Unix: `<runtime_dir>/control.sock`; Windows: `\\.\pipe\heimdall-<instance>-control`.
    pub control: PathBuf,
    /// Unix: `<runtime_dir>/signing.sock`; Windows: `\\.\pipe\heimdall-<instance>-signing`.
    pub signing: PathBuf,
}

impl EndpointPaths {
    /// Derive from the owner-only runtime directory (Unix) or an unpredictable
    /// instance token (Windows; names carry no labels, g03 §3.1 N2).
    ///
    /// Unix ignores `instance_token` (the owner-only directory is the namespace);
    /// Windows ignores `runtime_dir` (pipes live in the pipe namespace). The
    /// token is used verbatim: the runtime generates it from a CSPRNG and it must
    /// not carry user names or labels.
    #[must_use]
    pub fn for_runtime(runtime_dir: &Path, instance_token: &str) -> Self {
        #[cfg(windows)]
        {
            let _ = runtime_dir;
            let pipe = |kind: EndpointKind| {
                PathBuf::from(format!(
                    r"\\.\pipe\heimdall-{instance_token}-{}",
                    kind.name()
                ))
            };
            Self {
                control: pipe(EndpointKind::Control),
                signing: pipe(EndpointKind::Signing),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = instance_token;
            let sock = |kind: EndpointKind| runtime_dir.join(format!("{}.sock", kind.name()));
            Self {
                control: sock(EndpointKind::Control),
                signing: sock(EndpointKind::Signing),
            }
        }
    }

    /// Path for a kind.
    #[must_use]
    pub fn path(&self, kind: EndpointKind) -> &Path {
        match kind {
            EndpointKind::Control => &self.control,
            EndpointKind::Signing => &self.signing,
        }
    }
}

/// What the transport established about the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentity {
    /// Unix peer credentials.
    Unix {
        /// uid.
        uid: u32,
        /// gid.
        gid: u32,
        /// pid where the platform reports it (metadata only).
        pid: Option<i32>,
    },
    /// Windows client token user.
    Windows {
        /// SID string.
        sid: String,
        /// Client process ID (metadata only).
        pid: Option<u32>,
    },
}

/// Why a peer was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerRejected {
    /// A different OS user.
    #[error("peer is a different user")]
    DifferentUser,
    /// Credentials could not be obtained.
    #[error("peer credentials unavailable")]
    Unavailable,
    /// Remote client on a named pipe (must be rejected by flag and by check).
    #[error("remote clients are not accepted")]
    Remote,
}

/// Expected owner of the endpoints (the runtime's own principal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedOwner {
    /// Unix uid.
    Uid(u32),
    /// Windows SID.
    Sid(String),
}

/// Verify a peer against the expected owner. Pure; the same rule on every
/// platform: only the same OS user is accepted. Root/administrators are not
/// defended against (spec §14.1).
pub fn verify_peer(
    peer: &PeerIdentity,
    owner: &ExpectedOwner,
) -> Result<heimdall_contract::ipc::PrincipalInfo, PeerRejected> {
    match (peer, owner) {
        (PeerIdentity::Unix { uid, .. }, ExpectedOwner::Uid(expected)) if uid == expected => {
            Ok(heimdall_contract::ipc::PrincipalInfo::OsUserUnix { uid: *uid })
        }
        (PeerIdentity::Windows { sid, .. }, ExpectedOwner::Sid(expected))
            if sid.eq_ignore_ascii_case(expected) =>
        {
            Ok(heimdall_contract::ipc::PrincipalInfo::OsUserWindows { sid: sid.clone() })
        }
        _ => Err(PeerRejected::DifferentUser),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unix_paths_are_distinct_and_under_the_runtime_dir() {
        let dir = Path::new("/run/test-runtime/heimdall");
        let p = EndpointPaths::for_runtime(dir, "ignored");
        assert_eq!(p.control, dir.join("control.sock"));
        assert_eq!(p.signing, dir.join("signing.sock"));
        assert_ne!(p.path(EndpointKind::Control), p.path(EndpointKind::Signing));
        assert!(EndpointKind::Signing.max_frame_bytes() < EndpointKind::Control.max_frame_bytes());
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_names_carry_only_the_token() {
        let p = EndpointPaths::for_runtime(Path::new("C:\\ignored"), "0123abcd");
        assert_eq!(
            p.control,
            PathBuf::from(r"\\.\pipe\heimdall-0123abcd-control")
        );
        assert_eq!(
            p.signing,
            PathBuf::from(r"\\.\pipe\heimdall-0123abcd-signing")
        );
    }

    #[test]
    fn only_same_user_passes() {
        let me = ExpectedOwner::Uid(501);
        assert!(
            verify_peer(
                &PeerIdentity::Unix {
                    uid: 501,
                    gid: 20,
                    pid: None
                },
                &me
            )
            .is_ok()
        );
        assert_eq!(
            verify_peer(
                &PeerIdentity::Unix {
                    uid: 0,
                    gid: 0,
                    pid: None
                },
                &me
            ),
            Err(PeerRejected::DifferentUser)
        );
        assert_eq!(
            verify_peer(
                &PeerIdentity::Windows {
                    // Well-known BUILTIN\Users SID: synthetic, not a user account.
                    sid: "S-1-5-32-545".into(),
                    pid: None
                },
                &me
            ),
            Err(PeerRejected::DifferentUser)
        );
    }
}
