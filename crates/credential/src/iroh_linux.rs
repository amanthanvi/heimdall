//! `LinuxSecretServiceIroh` (ADR-0012 §2.4; m06-plan U56): K_iroh as an item of the Secret
//! Service **login** collection (`/org/freedesktop/secrets/collection/login`), read over a
//! **DH-encrypted session** (`EncryptionType::Dh`), one item per endpoint, labelled
//! [`item_label`] with the attributes `heimdall_application = heimdall-iroh`,
//! `heimdall_environment_id = <environment>` and `heimdall_endpoint_id = <endpoint>`. All
//! three are in every lookup and checked again on what the service reports, so each
//! installation sees, reads and destroys only its own endpoint's item.
//!
//! **Driving the async client from the synchronous trait** (as `mgmt::linux`): each
//! operation builds a current-thread tokio runtime (I/O and time) on a scoped thread of its
//! own, runs the whole exchange inside one `tokio::time::timeout` of [`OPERATION_BOUND`],
//! then drops the runtime. The thread keeps it safe to call from inside another runtime;
//! the bound keeps a stuck bus or a provider prompt from blocking the caller.
//!
//! Nothing here ever unlocks anything: a locked collection or item is
//! [`IrohStoreAvailability::Locked`]. A host with no Secret Service (headless Linux, WSL, a
//! container) is [`IrohStoreAvailability::Missing`], and the persistent Iroh endpoint is
//! unavailable there (ADR-0012 §2.4 item 3, §2.7). There is no plaintext fallback.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use heimdall_contract::ids::{EnvironmentId, IrohEndpointId};
use heimdall_contract::issuer::StoreKind;
use secret_service::{Collection, EncryptionType, SecretService};
use zeroize::Zeroizing;

use super::{
    ITEM_SERVICE, IrohKeyMaterial, IrohKeyStore, IrohStoreAvailability, IrohStoreError,
    IrohStoreKind, item_label,
};

/// The bound on one store operation (connect, negotiate, call).
pub const OPERATION_BOUND: Duration = Duration::from_secs(5);
/// The login collection's object path.
const LOGIN_COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
/// The secret's content type.
const CONTENT_TYPE: &str = "application/octet-stream";
/// Attribute: the application.
pub const ATTR_APPLICATION: &str = "heimdall_application";
/// Attribute: the environment ID (the installation).
pub const ATTR_ENVIRONMENT: &str = "heimdall_environment_id";
/// Attribute: the endpoint ID.
pub const ATTR_ENDPOINT: &str = "heimdall_endpoint_id";

fn service_error(e: &secret_service::Error) -> IrohStoreError {
    match e {
        secret_service::Error::Locked => IrohStoreError::Unavailable(IrohStoreAvailability::Locked),
        secret_service::Error::Prompt | secret_service::Error::PromptDisconnected => {
            IrohStoreError::Unavailable(IrohStoreAvailability::InteractionNotAllowed)
        }
        secret_service::Error::Unavailable
        | secret_service::Error::Zbus(_)
        | secret_service::Error::ZbusFdo(_) => {
            IrohStoreError::Unavailable(IrohStoreAvailability::Missing)
        }
        secret_service::Error::Crypto(_) | secret_service::Error::Zvariant(_) => {
            IrohStoreError::Unavailable(IrohStoreAvailability::Corrupt)
        }
        _ => IrohStoreError::Failed,
    }
}

/// Run `make()`'s future on a current-thread runtime of its own, on a scoped thread,
/// bounded by [`OPERATION_BOUND`] (module docs).
fn drive<T, F, Fut>(make: F) -> Result<T, IrohStoreError>
where
    T: Send,
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<T, IrohStoreError>>,
{
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| IrohStoreError::Unavailable(IrohStoreAvailability::Missing))?;
                runtime.block_on(async move {
                    match tokio::time::timeout(OPERATION_BOUND, make()).await {
                        Ok(result) => result,
                        Err(_) => Err(IrohStoreError::Unavailable(IrohStoreAvailability::Missing)),
                    }
                })
            })
            .join()
            .unwrap_or(Err(IrohStoreError::Failed))
    })
}

async fn connect() -> Result<SecretService<'static>, IrohStoreError> {
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|e| service_error(&e))
}

async fn unlocked_login<'a>(
    service: &'a SecretService<'a>,
) -> Result<Collection<'a>, IrohStoreError> {
    let collections = service
        .get_all_collections()
        .await
        .map_err(|e| service_error(&e))?;
    let collection = collections
        .into_iter()
        .find(|c| c.collection_path.as_str() == LOGIN_COLLECTION)
        .ok_or(IrohStoreError::Unavailable(IrohStoreAvailability::Missing))?;
    if collection
        .is_locked()
        .await
        .map_err(|e| service_error(&e))?
    {
        return Err(IrohStoreError::Unavailable(IrohStoreAvailability::Locked));
    }
    Ok(collection)
}

/// The Linux Secret Service K_iroh store of one installation.
#[derive(Debug, Clone)]
pub struct LinuxSecretServiceIroh {
    environment: EnvironmentId,
}

impl LinuxSecretServiceIroh {
    /// The store for the installation's `environment`.
    #[must_use]
    pub fn new(environment: &EnvironmentId) -> Self {
        Self {
            environment: environment.clone(),
        }
    }

    /// The attributes of `endpoint`'s item.
    fn scope<'a>(&'a self, endpoint: &'a IrohEndpointId) -> HashMap<&'a str, &'a str> {
        HashMap::from([
            (ATTR_APPLICATION, ITEM_SERVICE),
            (ATTR_ENVIRONMENT, self.environment.as_str()),
            (ATTR_ENDPOINT, endpoint.as_str()),
        ])
    }

    /// `endpoint`'s items among the collection's search results: searched with all three
    /// attributes, then checked again on what the service reported (fail closed if a
    /// service ignored an attribute).
    async fn mine<'a>(
        &self,
        collection: &'a Collection<'a>,
        endpoint: &IrohEndpointId,
    ) -> Result<Vec<secret_service::Item<'a>>, IrohStoreError> {
        let found = collection
            .search_items(self.scope(endpoint))
            .await
            .map_err(|e| service_error(&e))?;
        let mut mine = Vec::new();
        for item in found {
            let attributes = item.get_attributes().await.map_err(|e| service_error(&e))?;
            if attributes.get(ATTR_APPLICATION).map(String::as_str) == Some(ITEM_SERVICE)
                && attributes.get(ATTR_ENVIRONMENT).map(String::as_str)
                    == Some(self.environment.as_str())
                && attributes.get(ATTR_ENDPOINT).map(String::as_str) == Some(endpoint.as_str())
            {
                mine.push(item);
            }
        }
        Ok(mine)
    }
}

impl IrohKeyStore for LinuxSecretServiceIroh {
    fn kind(&self) -> IrohStoreKind {
        IrohStoreKind::Product(StoreKind::LinuxSecretService)
    }

    fn availability(&self) -> IrohStoreAvailability {
        let result = drive(|| async {
            let service = connect().await?;
            unlocked_login(&service).await.map(|_| ())
        });
        match result {
            Ok(()) => IrohStoreAvailability::Available,
            Err(IrohStoreError::Unavailable(a)) => a,
            Err(_) => IrohStoreAvailability::Missing,
        }
    }

    fn store_ref(&self, endpoint: &IrohEndpointId) -> String {
        item_label(&self.environment, endpoint)
    }

    fn put(&self, endpoint: &IrohEndpointId, key: &IrohKeyMaterial) -> Result<(), IrohStoreError> {
        key.check_endpoint(endpoint)?;
        let secret = key.to_store_bytes();
        let secret = &secret;
        let label = item_label(&self.environment, endpoint);
        let label = &label;
        drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            if !self.mine(&collection, endpoint).await?.is_empty() {
                return Err(IrohStoreError::AlreadyExists);
            }
            // `replace` is false: the service never overwrites an item with these
            // attributes, and the lookup above has just found none.
            collection
                .create_item(
                    label,
                    self.scope(endpoint),
                    secret.as_slice(),
                    false,
                    CONTENT_TYPE,
                )
                .await
                .map_err(|e| service_error(&e))?;
            Ok(())
        })
    }

    fn load(&self, endpoint: &IrohEndpointId) -> Result<IrohKeyMaterial, IrohStoreError> {
        let secret = drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let mut items = self.mine(&collection, endpoint).await?;
            let item = match items.len() {
                0 => return Err(IrohStoreError::NotFound),
                1 => items.swap_remove(0),
                // Two items for one endpoint: never guess which is the key.
                _ => return Err(IrohStoreError::Corrupt),
            };
            if item.is_locked().await.map_err(|e| service_error(&e))? {
                return Err(IrohStoreError::Unavailable(IrohStoreAvailability::Locked));
            }
            Ok(Zeroizing::new(
                item.get_secret().await.map_err(|e| service_error(&e))?,
            ))
        })?;
        IrohKeyMaterial::from_store_bytes(&secret, endpoint)
    }

    fn destroy(&self, endpoint: &IrohEndpointId) -> Result<(), IrohStoreError> {
        drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let mut items = self.mine(&collection, endpoint).await?;
            let item = match items.len() {
                0 => return Err(IrohStoreError::NotFound),
                1 => items.swap_remove(0),
                // Never delete by guess: a duplicate is for the owner to resolve.
                _ => return Err(IrohStoreError::Corrupt),
            };
            let path = item.item_path.as_str().to_owned();
            item.delete().await.map_err(|e| service_error(&e))?;
            if self
                .mine(&collection, endpoint)
                .await?
                .iter()
                .any(|i| i.item_path.as_str() == path)
            {
                return Err(IrohStoreError::Failed);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure checks only: no Secret Service exists on a build host, and the owner's
    /// collection is never touched by a test. The scope names the application, the
    /// installation and the endpoint; the kind is the product kind.
    #[test]
    fn iroh_linux_scope_names_application_installation_and_endpoint() {
        let environment = EnvironmentId::from_random_bytes([6; 16]);
        let endpoint = IrohKeyMaterial::from_bytes([1u8; 32]).endpoint_id();
        let store = LinuxSecretServiceIroh::new(&environment);
        assert_eq!(
            store.kind(),
            IrohStoreKind::Product(StoreKind::LinuxSecretService)
        );
        assert_eq!(store.kind().column(), "secret_service");
        let scope = store.scope(&endpoint);
        assert_eq!(scope.get(ATTR_APPLICATION), Some(&"heimdall-iroh"));
        assert_eq!(scope.get(ATTR_ENVIRONMENT), Some(&environment.as_str()));
        assert_eq!(scope.get(ATTR_ENDPOINT), Some(&endpoint.as_str()));
        assert_eq!(
            store.store_ref(&endpoint),
            item_label(&environment, &endpoint)
        );
    }
}
