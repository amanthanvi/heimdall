//! The service loop hosted by `heimdall service run` (spec §13.1; overview §4).

use std::sync::Arc;

use heimdall_app::Operations;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, Paths};
use crate::instance::InstanceLock;

/// Service start-up failure (mapped to `SERVICE_UNAVAILABLE`/`STATE_UNAVAILABLE`
/// by the CLI).
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Another instance is running.
    #[error(transparent)]
    Instance(#[from] crate::instance::InstanceError),
    /// Configuration.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// Store.
    #[error(transparent)]
    Store(#[from] heimdall_store::StoreError),
    /// Application start (restart recovery).
    #[error(transparent)]
    App(#[from] heimdall_app::OpError),
    /// Endpoint bind.
    #[error("endpoint bind failed: {0}")]
    Bind(std::io::Error),
}

/// A running service. Dropping it does not stop the loop; cancel the token.
#[derive(Debug)]
pub struct Service {
    _lock: InstanceLock,
    operations: Operations,
    shutdown: CancellationToken,
}

impl Service {
    /// Start-up order (R-RT-07, spec §13.3): acquire the instance lock → open and
    /// migrate the store → check time anchors → start operations (restart
    /// recovery) → bind control and signing endpoints → write `instance.json` →
    /// start the supervisor. Any failure before the endpoints are advertised
    /// leaves no advertisement behind.
    pub async fn start(
        _paths: Paths,
        _config: Config,
        _shutdown: CancellationToken,
    ) -> Result<Self, ServiceError> {
        todo!("M01-T05")
    }

    /// Serve until the token is cancelled or a fatal error occurs. Shutdown drains
    /// in-flight operations to a durable stage, closes endpoints, removes
    /// `instance.json`, and releases the lock last.
    pub async fn run(self) -> Result<(), ServiceError> {
        let _ = (&self.operations, &self.shutdown);
        todo!("M01-T05")
    }

    /// The application operations (for in-process callers such as tests).
    #[must_use]
    pub fn operations(&self) -> &Operations {
        &self.operations
    }

    /// Convenience: a current-thread tokio runtime configured for the service.
    pub fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }
}

/// Shared handle given to connection tasks.
#[derive(Clone)]
pub struct ServiceContext {
    /// Operations.
    pub operations: Operations,
    /// Shutdown token.
    pub shutdown: CancellationToken,
    /// Clock.
    pub clock: Arc<dyn heimdall_domain::time::Clock>,
}

impl std::fmt::Debug for ServiceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceContext").finish_non_exhaustive()
    }
}
