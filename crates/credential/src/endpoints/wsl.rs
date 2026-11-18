//! ⟨M04⟩ U4b: the Windows side of a WSL Mode B binding (ADR-0010 §3 items 5–6, 12): the
//! binding's endpoint is a socket **inside the distribution**, served by the helper, and each
//! stream the helper relays is served by the binding's [`ManagedSigner`] through the same
//! [`heimdall_ipc::signing::serve_with_limits`] path as the binding pipe
//! ([`serve_connection`]). Every signature therefore re-checks grant state, deadline, pause,
//! cutoff, generation and time (R-SE-07). A Mode B binding has no Windows pipe and no
//! listener here.
//!
//! **The seam.** The registry knows nothing of helpers: [`WslRealizer`] is what the runtime's
//! bridge supervisor (`heimdall_runtime::wsl_bridge`) implements. The registry
//!
//! * creates the binding's endpoint ([`EndpointRegistry::create_binding_at`] with
//!   [`super::EndpointPlacement::WslBridge`]): a fresh random tag, the locator
//!   `<run>/b/<tag>/agent.sock` from the realizer's run directory, and the binding's signer
//!   (no listener, no realization yet: the public material does not exist yet);
//! * realizes the binding's files and endpoint inside the distribution once the adapters hold
//!   the public material ([`EndpointRegistry::realize_wsl`]);
//! * serves a relayed stream ([`EndpointRegistry::serve_wsl_stream`]);
//! * withdraws exactly that generation when the endpoint is removed ([`super::Running::stop`]
//!   through the lease; a newer generation is never withdrawn, R-RT-04).
//!
//! Nothing here starts a distribution: [`WslRealizer::start`] is the one explicit call, made
//! only for the owner's own `ensure` naming the environment.

use std::io;
use std::sync::Arc;

use heimdall_app::ports::AdapterError;
use heimdall_contract::ids::{BindingId, EnvironmentId};
use heimdall_contract::provider::{EndpointKind as TransportKind, EndpointRef};
use heimdall_domain::resource::ResourceGeneration;
use heimdall_ipc::endpoint::{ExpectedOwner, PeerIdentity};

use super::{EndpointError, EndpointRegistry, EndpointTag, Running, serve_connection};

/// The public material a Mode B binding is realized with: certificate and public-key lines
/// (never a private key), the rendered `ssh_config` with the in-distribution paths already in
/// it, and the approved `known_hosts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslPublic {
    /// (file name, one OpenSSH line) per certificate and public key.
    pub files: Vec<(String, String)>,
    /// The rendered `ssh_config`.
    pub ssh_config: String,
    /// The approved host keys.
    pub known_hosts: String,
}

/// What the registry needs from the runtime's bridge supervisor. Every method blocks (the
/// helper channel is synchronous, bounded at 30 s): call them on the blocking pool.
pub trait WslRealizer: Send + Sync {
    /// The owner's explicit action names `environment` (an `ensure`): start its bridge when
    /// none runs, starting a stopped distribution if need be (ADR-0010 §3 item 9, §10 item 2).
    ///
    /// # Errors
    /// [`AdapterError::Unavailable`] naming `wsl_helper_unavailable`, `wsl_unavailable` or
    /// `wsl_distribution_not_running`.
    fn start(&self, environment: &EnvironmentId) -> Result<(), AdapterError>;

    /// The Linux run directory `<run>` of `environment`'s helper (an absolute path). It starts
    /// a bridge only when the distribution already runs, never a stopped one.
    ///
    /// # Errors
    /// As [`Self::start`].
    fn run_dir(&self, environment: &EnvironmentId) -> Result<String, AdapterError>;

    /// Realize `binding`'s endpoint `tag` at `generation` with `public`. Idempotent for the
    /// same tag and generation.
    ///
    /// # Errors
    /// As [`Self::start`]; `AdapterError::Protocol` for a refused file.
    fn realize(
        &self,
        environment: &EnvironmentId,
        binding: &BindingId,
        tag: &str,
        generation: u64,
        public: &WslPublic,
    ) -> Result<(), AdapterError>;

    /// Stop serving `environment`: its helper ends (the helper removes what it still
    /// serves). Called after every endpoint was withdrawn. Returns whether in-distribution
    /// leftovers remain a retained obligation (a withdrawal could not reach a stopped
    /// distribution), which the next helper start removes. `start` is the owner's explicit
    /// authorized start (`wsl disable --start`): only then may a stopped distribution be
    /// started to remove them now. Idempotent.
    ///
    /// # Errors
    /// [`AdapterError::Unavailable`].
    fn stop(&self, environment: &EnvironmentId, start: bool) -> Result<bool, AdapterError>;

    /// The helper's state of `environment`, for `inspect environments`.
    fn helper_state(
        &self,
        environment: &EnvironmentId,
    ) -> Option<heimdall_contract::environment::HelperState>;

    /// Withdraw `tag` at exactly `generation`. A helper that is gone has nothing to withdraw:
    /// the supervisor keeps the retained obligation and answers `Ok`.
    ///
    /// # Errors
    /// [`AdapterError::Unavailable`] when the helper could not be asked and no obligation
    /// could be kept.
    fn withdraw(
        &self,
        environment: &EnvironmentId,
        tag: &str,
        generation: u64,
    ) -> Result<(), AdapterError>;
}

/// A running Mode B endpoint's tie to its realizer, held by its [`Running`] entry.
pub(super) struct WslLease {
    pub(super) realizer: Arc<dyn WslRealizer>,
    pub(super) environment: EnvironmentId,
    pub(super) tag: String,
    pub(super) generation: u64,
}

impl WslLease {
    /// Withdraw this endpoint's generation (ends the lease's endpoint inside the
    /// distribution; the signer already refuses once the binding ended).
    pub(super) fn withdraw(&self) {
        let _ = self
            .realizer
            .withdraw(&self.environment, &self.tag, self.generation);
    }
}

/// The runtime's own principal as the peer of a relayed stream (ADR-0010 §3 item 6: the
/// Windows side admits a stream on the strength of the parent/child channel; the Linux
/// peer check is the endpoint's access control).
fn own_peer(owner: &ExpectedOwner) -> PeerIdentity {
    match owner {
        ExpectedOwner::Uid(uid) => PeerIdentity::Unix {
            uid: *uid,
            gid: *uid,
            pid: None,
        },
        ExpectedOwner::Sid(sid) => PeerIdentity::Windows {
            sid: sid.clone(),
            pid: None,
        },
    }
}

/// A weak handle to an [`EndpointRegistry`]: the bridge supervisor (which the registry holds
/// as its [`WslRealizer`]) keeps this, so the two never own each other.
#[derive(Clone)]
pub struct WeakEndpointRegistry(std::sync::Weak<super::RegistryInner>);

impl WeakEndpointRegistry {
    /// The registry, while it lives.
    #[must_use]
    pub fn upgrade(&self) -> Option<EndpointRegistry> {
        self.0.upgrade().map(|inner| EndpointRegistry { inner })
    }
}

impl EndpointRegistry {
    /// A weak handle to this registry.
    #[must_use]
    pub fn downgrade(&self) -> WeakEndpointRegistry {
        WeakEndpointRegistry(Arc::downgrade(&self.inner))
    }

    /// Install the runtime's bridge supervisor. Once; a second call is ignored (`false`).
    pub fn set_wsl_realizer(&self, realizer: Arc<dyn WslRealizer>) -> bool {
        self.inner.wsl.set(realizer).is_ok()
    }

    /// The owner's explicit start of `environment`'s bridge ([`WslRealizer::start`]).
    ///
    /// # Errors
    /// [`AdapterError::Unavailable`]; without a realizer, `wsl_unavailable`.
    pub fn start_wsl_environment(&self, environment: &EnvironmentId) -> Result<(), AdapterError> {
        self.inner
            .wsl
            .get()
            .ok_or_else(|| AdapterError::Unavailable("wsl_unavailable".to_owned()))?
            .start(environment)
    }

    /// Whether a bridge supervisor is installed.
    #[must_use]
    pub fn has_wsl_realizer(&self) -> bool {
        self.inner.wsl.get().is_some()
    }

    /// The helper's state of `environment` (`None` without a supervisor).
    #[must_use]
    pub fn wsl_helper_state(
        &self,
        environment: &EnvironmentId,
    ) -> Option<heimdall_contract::environment::HelperState> {
        self.inner.wsl.get()?.helper_state(environment)
    }

    /// Stop every Mode B endpoint of `environment` (each withdrawn by its generation), then
    /// its helper ([`WslRealizer::stop`]). Idempotent. Returns whether in-distribution
    /// leftovers remain a retained obligation.
    ///
    /// # Errors
    /// [`AdapterError::Unavailable`] without a supervisor.
    pub fn stop_wsl_environment(
        &self,
        environment: &EnvironmentId,
        start: bool,
    ) -> Result<bool, AdapterError> {
        let realizer = self
            .inner
            .wsl
            .get()
            .cloned()
            .ok_or_else(|| AdapterError::Unavailable("wsl_unavailable".to_owned()))?;
        let stopped = {
            let mut s = self.inner.lock();
            let mut out = Vec::new();
            s.bindings.retain(|_, gens| {
                let at: Vec<ResourceGeneration> = gens
                    .iter()
                    .filter(|(_, r)| {
                        r.wsl
                            .as_ref()
                            .is_some_and(|l| l.environment == *environment)
                    })
                    .map(|(g, _)| *g)
                    .collect();
                for g in at {
                    if let Some(r) = gens.remove(&g) {
                        out.push(r);
                    }
                }
                !gens.is_empty()
            });
            out
        };
        for r in stopped {
            r.stop();
        }
        realizer.stop(environment, start)
    }

    pub(super) fn create_binding_wsl(
        &self,
        binding: &BindingId,
        generation: ResourceGeneration,
        environment: &EnvironmentId,
    ) -> Result<EndpointRef, EndpointError> {
        let realizer = self
            .inner
            .wsl
            .get()
            .cloned()
            .ok_or_else(|| EndpointError::Wsl("wsl_unavailable".to_owned()))?;
        if self
            .inner
            .lock()
            .bindings
            .get(binding)
            .is_some_and(|g| g.contains_key(&generation))
        {
            return Err(EndpointError::AlreadyRunning);
        }
        let tag = EndpointTag::generate().map_err(|_| EndpointError::RandomnessUnavailable)?;
        let run_dir = realizer.run_dir(environment).map_err(|e| match e {
            AdapterError::Unavailable(m) | AdapterError::Protocol(m) => EndpointError::Wsl(m),
            _ => EndpointError::Wsl("wsl_helper_unavailable".to_owned()),
        })?;
        if !run_dir.starts_with('/') || run_dir.contains(['\0', '\n', '\r']) {
            return Err(EndpointError::Wsl("wsl_helper_unavailable".to_owned()));
        }
        let endpoint = EndpointRef {
            kind: TransportKind::UnixSocket,
            locator: format!(
                "{}/b/{tag}/{}",
                run_dir.trim_end_matches('/'),
                super::AGENT_SOCKET
            ),
        };
        let signer = self
            .inner
            .signer(heimdall_app::ports::SignerEndpoint::Binding(
                binding.clone(),
            ));
        let running = Running {
            endpoint: endpoint.clone(),
            signer,
            stop: self.inner.shutdown.child_token(),
            task: None,
            dir: None,
            identity: None,
            wsl: Some(WslLease {
                realizer,
                environment: environment.clone(),
                tag: tag.as_str().to_owned(),
                generation: generation.0,
            }),
        };
        let mut s = self.inner.lock();
        let gens = s.bindings.entry(binding.clone()).or_default();
        if gens.contains_key(&generation) {
            drop(s);
            running.stop();
            return Err(EndpointError::AlreadyRunning);
        }
        gens.insert(generation, running);
        Ok(endpoint)
    }

    /// Realize `binding`'s Mode B endpoint of `generation` inside its distribution with
    /// `public` (the adapters call it once the files' content exists). Blocking.
    ///
    /// # Errors
    /// [`AdapterError::Unavailable`] when `binding` has no Mode B endpoint of that
    /// generation or the realizer refuses.
    pub fn realize_wsl(
        &self,
        binding: &BindingId,
        generation: ResourceGeneration,
        public: &WslPublic,
    ) -> Result<(), AdapterError> {
        let (realizer, environment, tag) = {
            let s = self.inner.lock();
            let lease = s
                .bindings
                .get(binding)
                .and_then(|g| g.get(&generation))
                .and_then(|r| r.wsl.as_ref())
                .ok_or_else(|| {
                    AdapterError::Unavailable("binding_endpoint_unavailable".to_owned())
                })?;
            (
                Arc::clone(&lease.realizer),
                lease.environment.clone(),
                lease.tag.clone(),
            )
        };
        realizer.realize(&environment, binding, &tag, generation.0, public)
    }

    /// Serve one stream the helper relayed from `binding`'s Mode B endpoint of `generation`
    /// with that binding's signer, on `runtime` (the helper's reader thread calls this and
    /// must not block). `false` refuses the stream: the binding has no such endpoint, so no
    /// signer.
    #[must_use]
    pub fn serve_wsl_stream(
        &self,
        runtime: &tokio::runtime::Handle,
        binding: &BindingId,
        generation: ResourceGeneration,
        stream: tokio::io::DuplexStream,
    ) -> bool {
        let (signer, endpoint, stop) = {
            let s = self.inner.lock();
            let Some(r) = s
                .bindings
                .get(binding)
                .and_then(|g| g.get(&generation))
                .filter(|r| r.wsl.is_some())
            else {
                return false;
            };
            (
                Arc::clone(&r.signer),
                r.endpoint.clone(),
                r.stop.child_token(),
            )
        };
        let owner = self.inner.owner.clone();
        let peer = own_peer(&owner);
        let limits = self.inner.limits.serve;
        runtime.spawn(async move {
            let _: io::Result<()> =
                serve_connection(stream, peer, endpoint, signer, &owner, limits, stop).await;
        });
        true
    }
}
