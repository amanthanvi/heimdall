//! ⟨M04⟩ U5: the container environment's signing endpoint (`<runtime_dir>/c/<16 hex>/
//! agent.sock`, ADR-0010 §4 items 1–6): one active binding per container environment, the
//! `SO_PEERCRED` UID rule, generation-checked teardown.
//!
//! **The directory** is the environment's stable one, created with the environment (0700)
//! and never removed by a binding's teardown; the registry places a binding's endpoint in it
//! ([`super::EndpointPlacement::Container`], [`super::EndpointRegistry::create_binding_at`]).
//! Its other entries (the key, certificates, `ssh_config`, `known_hosts`) are the adapters'
//! (`heimdall_adapters::managed::files`), fenced by the generation marker.
//!
//! **The UID rule (ADR-0010 §4 item 5)** is not a container rule at all. Every connection to
//! this endpoint goes through [`super::serve_connection`], which admits a peer only when
//! `verify_peer` finds its uid equal to the runtime's: the peer's `SO_PEERCRED` uid as the
//! kernel reports it **in the runtime's user namespace** (`ipc::unix::Listener::accept`,
//! tokio's `peer_cred`). In practice:
//!
//! * a rootless engine maps container root (and Podman's `--userns=keep-id` user) to the
//!   runtime's uid, so it is admitted;
//! * a rootful engine's container run as `--user <uid>:<gid>` carries the runtime's uid, so it
//!   is admitted;
//! * rootful root (uid 0), an unmapped sub-uid and any other user are refused by the same
//!   comparison, before a byte is read.
//!
//! Same-uid processes on the host can use the endpoint too (spec §14.1; ADR-0010 §4
//! non-claims: not a sandbox).

use std::path::{Path, PathBuf};

use super::{AGENT_SOCKET, CONTAINER_DIR, EndpointTag};

/// A container environment's stable directory, `<runtime_dir>/c/<tag>`.
#[must_use]
pub fn container_dir(runtime_dir: &Path, tag: &EndpointTag) -> PathBuf {
    runtime_dir.join(CONTAINER_DIR).join(tag.as_str())
}

/// The signing endpoint inside it, `<runtime_dir>/c/<tag>/agent.sock`.
#[must_use]
pub fn container_socket(runtime_dir: &Path, tag: &EndpointTag) -> PathBuf {
    container_dir(runtime_dir, tag).join(AGENT_SOCKET)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use heimdall_ipc::endpoint::{ExpectedOwner, PeerIdentity};

    use super::super::peer_admitted;

    /// ADR-0010 §4 item 5: the endpoint's admission is the runtime's own uid comparison on
    /// the kernel-translated `SO_PEERCRED` uid, with no container-specific rule: the mapped
    /// user is admitted, rootful root and an unmapped sub-uid are not.
    #[test]
    fn the_uid_rule_admits_the_mapped_owner_and_refuses_root_and_sub_uids() {
        let runtime_uid = 1000;
        let owner = ExpectedOwner::Uid(runtime_uid);
        let peer = |uid| PeerIdentity::Unix {
            uid,
            gid: uid,
            pid: None,
        };
        assert!(
            peer_admitted(&peer(runtime_uid), &owner),
            "keep-id / --user <uid>"
        );
        assert!(!peer_admitted(&peer(0), &owner), "rootful root");
        assert!(
            !peer_admitted(&peer(100_999), &owner),
            "an unmapped sub-uid"
        );
        assert!(!peer_admitted(&peer(1001), &owner), "another user");
    }
}
