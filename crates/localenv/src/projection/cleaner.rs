//! The cleaner for projection resources (m02-plan U4; ADR-0007 §5.8, rows R1–R6).
//!
//! It deletes only when the generation matches **and** the entry has the identity and
//! digest in the `ProjectionLocator`, through the quarantine at the slot derived from
//! the locator (so a retry finds an entry moved before a crash), re-checking the
//! digest in the slot before removal. Otherwise it returns `Ok` with nothing deleted.

use async_trait::async_trait;
use heimdall_app::ports::{AdapterError, ResourceCleaner};
use heimdall_domain::resource::ManagedResource;

use super::ProjectionConfig;

/// The `ResourceCleaner` for `config_projection` resources.
#[derive(Debug, Clone)]
pub struct ProjectionCleaner {
    config: ProjectionConfig,
}

impl ProjectionCleaner {
    /// A cleaner over `config`.
    #[must_use]
    pub fn new(config: ProjectionConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ResourceCleaner for ProjectionCleaner {
    async fn delete(&self, resource: &ManagedResource) -> Result<(), AdapterError> {
        let _ = (&self.config, resource);
        todo!("M02-U4 projection::cleaner::ProjectionCleaner::delete")
    }
}
