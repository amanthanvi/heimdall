//! ⟨M04 U3b⟩ The runtime's WSL wiring (ADR-0010 §2, §9 item 2; m04-plan U3).
//!
//! * [`NamespaceCleaner`]: the supervisor's cleaner for `config_projection` resources,
//!   routing by the resource's projection namespace. A resource of the runtime's own
//!   namespace goes to the native cleaner, as before. A resource of a WSL distribution's
//!   namespace (its `distribution_git` item) goes to that distribution's helper cleaner,
//!   and never starts the distribution (`DistributionStart::Forbidden`). While the
//!   distribution is stopped, or its helper unavailable, the deletion fails and stays
//!   the executor's retained, retried obligation. It is never claimed done.
//!
//! The host itself (`heimdall_wsl::WslHost` on Windows) is installed with
//! `Operations::set_distribution_host`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use heimdall_app::ports::{AdapterError, DistributionHost, DistributionStart, ResourceCleaner};
use heimdall_contract::ids::EnvironmentId;
use heimdall_domain::resource::{ManagedResource, OwnerRef, ResourceKind};
use heimdall_store::Store;

/// The `config_projection` cleaner that routes a distribution namespace's resources to
/// its helper (module docs).
pub struct NamespaceCleaner {
    native: Arc<dyn ResourceCleaner>,
    own: EnvironmentId,
    store: Arc<Store>,
    host: Option<Arc<dyn DistributionHost>>,
}

impl NamespaceCleaner {
    /// Route `own`'s resources (and anything that is not a projection resource) to
    /// `native`, and a distribution namespace's to `host`'s cleaner for it.
    #[must_use]
    pub fn new(
        native: Arc<dyn ResourceCleaner>,
        own: EnvironmentId,
        store: Arc<Store>,
        host: Option<Arc<dyn DistributionHost>>,
    ) -> Self {
        Self {
            native,
            own,
            store,
            host,
        }
    }
}

/// The projection namespace a resource belongs to, when it is a projection resource.
fn namespace_of(resource: &ManagedResource) -> Option<&EnvironmentId> {
    match (&resource.kind, &resource.owner) {
        (ResourceKind::ConfigProjection, OwnerRef::Projection { environment }) => Some(environment),
        _ => None,
    }
}

impl NamespaceCleaner {
    async fn route(&self, resource: &ManagedResource) -> Result<(), AdapterError> {
        let Some(ns) = namespace_of(resource).filter(|ns| **ns != self.own) else {
            return self.native.delete(resource).await;
        };
        let ns = ns.clone();
        let store = Arc::clone(&self.store);
        let record = tokio::task::spawn_blocking(move || {
            store.transaction(|tx| {
                Ok(tx
                    .wsl_distributions()?
                    .into_iter()
                    .find(|r| r.namespace.as_ref() == Some(&ns)))
            })
        })
        .await
        .map_err(|_| AdapterError::Unavailable("the namespace lookup task failed".to_owned()))?
        .map_err(|e| AdapterError::Unavailable(format!("the store is unavailable: {e}")))?;
        // A resource of a namespace no distribution record holds is never deleted here:
        // whose files they are cannot be established, so it stays for the owner.
        let target = record
            .as_ref()
            .and_then(heimdall_app::operations::wsl_m04::mode_a_target)
            .ok_or_else(|| {
                AdapterError::Unavailable(
                    "the resource's distribution is unknown to this runtime".to_owned(),
                )
            })?;
        let host = self.host.clone().ok_or_else(|| {
            AdapterError::Unavailable(
                heimdall_contract::envelope::reason::WSL_UNAVAILABLE.to_owned(),
            )
        })?;
        let cleaner = tokio::task::spawn_blocking(move || {
            host.cleaner(&target, DistributionStart::Forbidden)
        })
        .await
        .map_err(|_| {
            AdapterError::Unavailable("the distribution cleaner task failed".to_owned())
        })??;
        cleaner.delete(resource).await
    }
}

// `ResourceCleaner` is declared with `#[async_trait]`; this is the desugared form (as
// `connections.rs` and `dispatch.rs` do), delegating to [`NamespaceCleaner::route`].
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl ResourceCleaner for NamespaceCleaner {
    fn delete<'life0, 'life1, 'async_trait>(
        &'life0 self,
        resource: &'life1 ManagedResource,
    ) -> BoxFuture<'async_trait, Result<(), AdapterError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.route(resource))
    }
}
