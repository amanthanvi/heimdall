//! The per-session K_mgmt agent's signer (ADR-0012 §3.4, R-SE-06): the identity `ssh`
//! sees through the isolated configuration's `IdentityAgent`, served only for the lifetime
//! of one management session.
//!
//! It lists exactly one identity, K_mgmt, and signs only an SSH user-authentication request
//! ([`crate::purpose::parse_userauth`]) that presents K_mgmt's own key as `ssh-ed25519`,
//! with no signature flags, for one of the session's runner accounts, and, for the
//! host-bound method, for one of the session's pinned runner host keys. Everything else
//! (Git or file signatures, another key, another account, another host) is
//! `SSH_AGENT_FAILURE`. Session-bind requests are refused (OpenSSH continues without one).

use std::collections::BTreeSet;

use heimdall_ipc::signing::{SignOutcome, Signer, SigningSession};

use super::{KEY_COMMENT, MgmtKey, MgmtKeyError};
use crate::purpose::{UserAuthMethod, parse_userauth};

/// The K_mgmt signer of one management session.
pub struct MgmtSigner {
    key: MgmtKey,
    blob: Vec<u8>,
    users: BTreeSet<String>,
    host_keys: BTreeSet<Vec<u8>>,
}

impl std::fmt::Debug for MgmtSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MgmtSigner")
            .field("users", &self.users)
            .finish_non_exhaustive()
    }
}

impl MgmtSigner {
    /// A signer for `key` that signs only for `users` (the runner accounts) and, on the
    /// host-bound method, only for `host_keys` (the pinned runner host keys, SSH wire
    /// encoding).
    ///
    /// # Errors
    /// [`MgmtKeyError::Encoding`].
    pub fn new(
        key: MgmtKey,
        users: impl IntoIterator<Item = String>,
        host_keys: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<MgmtSigner, MgmtKeyError> {
        let blob = key.public()?.blob;
        Ok(MgmtSigner {
            key,
            blob,
            users: users.into_iter().collect(),
            host_keys: host_keys.into_iter().collect(),
        })
    }

    /// [`MgmtSigner::new`] with the pinned runner host keys given as OpenSSH public key lines
    /// (the management record's pins).
    ///
    /// # Errors
    /// [`MgmtKeyError::Encoding`], also for a line that is not one public key.
    pub fn with_host_key_lines(
        key: MgmtKey,
        users: impl IntoIterator<Item = String>,
        host_key_lines: &[String],
    ) -> Result<MgmtSigner, MgmtKeyError> {
        let mut blobs = Vec::with_capacity(host_key_lines.len());
        for line in host_key_lines {
            let key = ssh_key::PublicKey::from_openssh(line.trim())
                .map_err(|_| MgmtKeyError::Encoding)?;
            blobs.push(key.to_bytes().map_err(|_| MgmtKeyError::Encoding)?);
        }
        MgmtSigner::new(key, users, blobs)
    }

    /// Whether `data` (with `key_blob` and `flags`) is a request this signer may sign.
    fn admits(&self, key_blob: &[u8], data: &[u8], flags: u32) -> bool {
        if key_blob != self.blob.as_slice() || flags != 0 {
            return false;
        }
        let Ok(request) = parse_userauth(data) else {
            return false;
        };
        if request.key_blob != self.blob
            || request.algorithm != "ssh-ed25519"
            || !self.users.contains(&request.user)
        {
            return false;
        }
        match &request.method {
            UserAuthMethod::Publickey => true,
            UserAuthMethod::PublickeyHostbound { server_host_key } => {
                self.host_keys.contains(server_host_key)
            }
        }
    }
}

#[async_trait::async_trait]
impl Signer for MgmtSigner {
    async fn identities(&self, _session: &SigningSession) -> Vec<(Vec<u8>, String)> {
        vec![(self.blob.clone(), KEY_COMMENT.to_owned())]
    }

    async fn sign(
        &self,
        _session: &SigningSession,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> SignOutcome {
        if !self.admits(key_blob, data, flags) {
            return SignOutcome::failure();
        }
        // K_mgmt is not a grant key: no signing gate or permit exists for it, so the
        // signature is declared ungated (ADR-0008 §17.15 names this case for keys outside
        // any grant).
        match self.key.sign(data) {
            Ok(signature) => SignOutcome::ungated_signature(&signature),
            Err(_) => SignOutcome::failure(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_ipc::endpoint::PeerIdentity;
    use heimdall_ipc::signing::failure_frame;
    use ssh_encoding::Encode as _;

    use super::*;

    fn userauth(user: &str, method: &str, key_blob: &[u8], host_key: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        [7u8; 32].as_slice().encode(&mut out).unwrap();
        out.push(50);
        user.encode(&mut out).unwrap();
        "ssh-connection".encode(&mut out).unwrap();
        method.encode(&mut out).unwrap();
        out.push(1);
        "ssh-ed25519".encode(&mut out).unwrap();
        key_blob.encode(&mut out).unwrap();
        if let Some(h) = host_key {
            h.encode(&mut out).unwrap();
        }
        out
    }

    fn session() -> SigningSession {
        SigningSession::new(
            PeerIdentity::Unix {
                uid: 0,
                gid: 0,
                pid: None,
            },
            EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: "/run/mgmt-agent.sock".into(),
            },
        )
    }

    #[tokio::test]
    async fn signs_only_userauth_for_k_mgmt_its_account_and_pinned_host() {
        let key = MgmtKey::generate().unwrap();
        let blob = key.public().unwrap().blob;
        let host = MgmtKey::generate().unwrap().public().unwrap().blob;
        let other_host = MgmtKey::generate().unwrap().public().unwrap().blob;
        let signer = MgmtSigner::new(key, ["runner".to_owned()], [host.clone()]).unwrap();
        let s = session();
        assert_eq!(
            signer.identities(&s).await,
            vec![(blob.clone(), KEY_COMMENT.to_owned())]
        );
        let ok = userauth("runner", "publickey", &blob, None);
        let signed = signer.sign(&s, &blob, &ok, 0).await;
        assert!(signed.ungated && signed.frame != failure_frame());
        let bound = userauth(
            "runner",
            "publickey-hostbound-v00@openssh.com",
            &blob,
            Some(&host),
        );
        assert!(signer.sign(&s, &blob, &bound, 0).await.ungated);
        let failure = failure_frame().to_vec();
        for (why, data, flags) in [
            (
                "another account",
                userauth("root", "publickey", &blob, None),
                0,
            ),
            (
                "an unpinned host",
                userauth(
                    "runner",
                    "publickey-hostbound-v00@openssh.com",
                    &blob,
                    Some(&other_host),
                ),
                0,
            ),
            ("a flag", ok.clone(), 2),
            ("not a userauth request", b"SSHSIG-ish payload".to_vec(), 0),
            (
                "another key",
                userauth("runner", "publickey", &other_host, None),
                0,
            ),
        ] {
            let out = signer.sign(&s, &blob, &data, flags).await;
            assert_eq!(out.frame, failure, "{why}");
        }
        // A request naming another key blob at the agent level.
        assert_eq!(signer.sign(&s, &host, &ok, 0).await.frame, failure);
    }
}
