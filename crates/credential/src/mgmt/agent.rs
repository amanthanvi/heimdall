//! The per-session K_mgmt agent (ADR-0012 §3.4, §5.2): an owner-only socket that serves one
//! [`MgmtSigner`] for the lifetime of one management session, named by the isolated
//! configuration's `IdentityAgent`. Same-user peers only (the transport's peer credentials);
//! stopped and unlinked when the session ends ([`SessionAgent::stop`], or on drop).
//!
//! **Unix only in this build.** A Windows named-pipe agent for K_mgmt is not wired yet: the
//! controller refuses management sessions there before K_mgmt is read (DONE question U2-Q6).

use std::io;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use heimdall_contract::provider::{EndpointKind as ProviderEndpointKind, EndpointRef};
#[cfg(unix)]
use heimdall_ipc::endpoint::{EndpointKind, PeerIdentity};
#[cfg(unix)]
use heimdall_ipc::signing::{Signer, serve};
use tokio_util::sync::CancellationToken;

use super::MgmtSigner;

/// A running per-session agent.
#[derive(Debug)]
pub struct SessionAgent {
    path: PathBuf,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl SessionAgent {
    /// Bind an owner-only socket at `path` (its directory is created owner-only when
    /// missing; a live or foreign socket there is refused) and serve `signer` to peers of
    /// this user until stopped. Must be called inside a tokio runtime.
    ///
    /// # Errors
    /// The bind's I/O error.
    #[cfg(unix)]
    pub fn start(path: &Path, signer: MgmtSigner) -> io::Result<SessionAgent> {
        let listener = heimdall_ipc::unix::Listener::bind(path, EndpointKind::Signing)?;
        let stop = CancellationToken::new();
        let signer: Arc<dyn Signer> = Arc::new(signer);
        let endpoint = EndpointRef {
            kind: ProviderEndpointKind::UnixSocket,
            locator: path.to_string_lossy().into_owned(),
        };
        let uid = heimdall_ipc::unix::current_uid();
        let token = stop.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = token.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else { break };
                        let same_user = matches!(peer, PeerIdentity::Unix { uid: u, .. } if u == uid);
                        if !same_user {
                            continue;
                        }
                        let signer = signer.clone();
                        let endpoint = endpoint.clone();
                        let token = token.clone();
                        tokio::spawn(async move {
                            let _ = serve(stream, peer, endpoint, signer, token).await;
                        });
                    }
                }
            }
            drop(listener);
        });
        Ok(SessionAgent {
            path: path.to_path_buf(),
            stop,
            task: Some(task),
        })
    }

    /// Not available on this platform in this build (module docs).
    ///
    /// # Errors
    /// Always `Unsupported`.
    #[cfg(not(unix))]
    pub fn start(path: &Path, signer: MgmtSigner) -> io::Result<SessionAgent> {
        let _ = (path, signer);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the management key agent is not available on this platform in this build",
        ))
    }

    /// The socket path (the `IdentityAgent` the configuration names).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop serving, wait for the listener to close, and unlink the socket.
    pub async fn stop(mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for SessionAgent {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::MgmtKey;
    use super::*;

    /// The agent lists exactly K_mgmt to a same-user client and is gone after `stop`.
    #[tokio::test]
    async fn serves_k_mgmt_then_unlinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("agent.sock");
        let key = MgmtKey::generate().unwrap();
        let blob = key.public().unwrap().blob;
        let agent = SessionAgent::start(&path, MgmtSigner::new(key, ["u".to_owned()], []).unwrap())
            .unwrap();
        let mut client = tokio::net::UnixStream::connect(agent.path()).await.unwrap();
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        // SSH2_AGENTC_REQUEST_IDENTITIES (11).
        client.write_all(&[0, 0, 0, 1, 11]).await.unwrap();
        let mut len = [0u8; 4];
        client.read_exact(&mut len).await.unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(body[0], 12, "SSH2_AGENT_IDENTITIES_ANSWER");
        assert_eq!(u32::from_be_bytes([body[1], body[2], body[3], body[4]]), 1);
        let blob_len = u32::from_be_bytes([body[5], body[6], body[7], body[8]]) as usize;
        assert_eq!(&body[9..9 + blob_len], blob.as_slice());
        drop(client);
        agent.stop().await;
        assert!(!path.exists(), "the socket is unlinked");
    }
}
