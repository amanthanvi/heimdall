//! `LinuxSecretServiceMgmt` (ADR-0012 §3.4; ADR-0005 §5.1/§5.2; m06-plan U2): K_mgmt as an
//! item of the Secret Service **login** collection
//! (`/org/freedesktop/secrets/collection/login`), read over a **DH-encrypted session**
//! (`EncryptionType::Dh`), labelled [`item_label`] with the attributes
//! `heimdall_application = heimdall-mgmt` and `heimdall_environment_id = <environment>`.
//! The environment ID is in every lookup, so two installations of one OS user keep two
//! items and each sees, reads and destroys only its own.
//!
//! **Driving the async client from the synchronous trait.** Each operation builds a
//! current-thread tokio runtime (I/O and time) on a scoped thread of its own, runs the
//! whole exchange (connect, session negotiation, the call) inside one
//! `tokio::time::timeout` of [`OPERATION_BOUND`], then drops the runtime, which cancels
//! zbus's tasks. The thread keeps it safe to call from inside another runtime without
//! nesting; the bound keeps a stuck bus or a provider prompt from blocking the caller.
//!
//! Nothing here ever unlocks anything (`unlock`/`ensure_unlocked` are never used): a
//! locked collection or item is [`MgmtStoreAvailability::Locked`]
//! (`mgmt_key_store_locked`). A host with no Secret Service (headless Linux, a container)
//! is [`MgmtStoreAvailability::Missing`]. There is no plaintext fallback.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::issuer::StoreKind;
use secret_service::{Collection, EncryptionType, SecretService};
use zeroize::Zeroizing;

use super::{
    ITEM_SERVICE, MgmtKey, MgmtKeyStore, MgmtStoreAvailability, MgmtStoreError, MgmtStoreKind,
    item_label,
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

fn service_error(e: &secret_service::Error) -> MgmtStoreError {
    match e {
        secret_service::Error::Locked => MgmtStoreError::Unavailable(MgmtStoreAvailability::Locked),
        secret_service::Error::Prompt | secret_service::Error::PromptDisconnected => {
            MgmtStoreError::Unavailable(MgmtStoreAvailability::InteractionNotAllowed)
        }
        secret_service::Error::Unavailable
        | secret_service::Error::Zbus(_)
        | secret_service::Error::ZbusFdo(_) => {
            MgmtStoreError::Unavailable(MgmtStoreAvailability::Missing)
        }
        secret_service::Error::Crypto(_) | secret_service::Error::Zvariant(_) => {
            MgmtStoreError::Unavailable(MgmtStoreAvailability::Corrupt)
        }
        _ => MgmtStoreError::Failed,
    }
}

/// Run `make()`'s future on a current-thread runtime of its own, on a scoped thread,
/// bounded by [`OPERATION_BOUND`] (module docs).
fn drive<T, F, Fut>(make: F) -> Result<T, MgmtStoreError>
where
    T: Send,
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<T, MgmtStoreError>>,
{
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| MgmtStoreError::Unavailable(MgmtStoreAvailability::Missing))?;
                runtime.block_on(async move {
                    match tokio::time::timeout(OPERATION_BOUND, make()).await {
                        Ok(result) => result,
                        Err(_) => Err(MgmtStoreError::Unavailable(MgmtStoreAvailability::Missing)),
                    }
                })
            })
            .join()
            .unwrap_or(Err(MgmtStoreError::Failed))
    })
}

async fn connect() -> Result<SecretService<'static>, MgmtStoreError> {
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|e| service_error(&e))
}

async fn unlocked_login<'a>(
    service: &'a SecretService<'a>,
) -> Result<Collection<'a>, MgmtStoreError> {
    let collections = service
        .get_all_collections()
        .await
        .map_err(|e| service_error(&e))?;
    let collection = collections
        .into_iter()
        .find(|c| c.collection_path.as_str() == LOGIN_COLLECTION)
        .ok_or(MgmtStoreError::Unavailable(MgmtStoreAvailability::Missing))?;
    if collection
        .is_locked()
        .await
        .map_err(|e| service_error(&e))?
    {
        return Err(MgmtStoreError::Unavailable(MgmtStoreAvailability::Locked));
    }
    Ok(collection)
}

/// The Linux Secret Service K_mgmt store of one installation.
#[derive(Debug, Clone)]
pub struct LinuxSecretServiceMgmt {
    environment: String,
    label: String,
}

impl LinuxSecretServiceMgmt {
    /// The store for the installation's `environment`.
    #[must_use]
    pub fn new(environment: &EnvironmentId) -> Self {
        Self {
            environment: environment.as_str().to_owned(),
            label: item_label(environment),
        }
    }

    /// The attributes of this installation's item.
    fn scope(&self) -> HashMap<&str, &str> {
        HashMap::from([
            (ATTR_APPLICATION, ITEM_SERVICE),
            (ATTR_ENVIRONMENT, self.environment.as_str()),
        ])
    }

    /// This installation's items among the collection's search results: searched with the
    /// environment in the attributes, then checked again on what the service reported
    /// (fail closed if a service ignored an attribute).
    async fn mine<'a>(
        &self,
        collection: &'a Collection<'a>,
    ) -> Result<Vec<secret_service::Item<'a>>, MgmtStoreError> {
        let found = collection
            .search_items(self.scope())
            .await
            .map_err(|e| service_error(&e))?;
        let mut mine = Vec::new();
        for item in found {
            let attributes = item.get_attributes().await.map_err(|e| service_error(&e))?;
            if attributes.get(ATTR_APPLICATION).map(String::as_str) == Some(ITEM_SERVICE)
                && attributes.get(ATTR_ENVIRONMENT).map(String::as_str)
                    == Some(self.environment.as_str())
            {
                mine.push(item);
            }
        }
        Ok(mine)
    }
}

impl MgmtKeyStore for LinuxSecretServiceMgmt {
    fn kind(&self) -> MgmtStoreKind {
        MgmtStoreKind::Product(StoreKind::LinuxSecretService)
    }

    fn availability(&self) -> MgmtStoreAvailability {
        let result = drive(|| async {
            let service = connect().await?;
            unlocked_login(&service).await.map(|_| ())
        });
        match result {
            Ok(()) => MgmtStoreAvailability::Available,
            Err(MgmtStoreError::Unavailable(a)) => a,
            Err(_) => MgmtStoreAvailability::Missing,
        }
    }

    fn put(&self, key: &MgmtKey) -> Result<(), MgmtStoreError> {
        let secret = key.to_store_bytes();
        let secret = &secret;
        drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            if !self.mine(&collection).await?.is_empty() {
                return Err(MgmtStoreError::AlreadyExists);
            }
            // `replace` is false: the service never overwrites an item with these
            // attributes, and the lookup above has just found none.
            collection
                .create_item(
                    &self.label,
                    self.scope(),
                    secret.as_slice(),
                    false,
                    CONTENT_TYPE,
                )
                .await
                .map_err(|e| service_error(&e))?;
            Ok(())
        })
    }

    fn load(&self) -> Result<MgmtKey, MgmtStoreError> {
        let secret = drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let mut items = self.mine(&collection).await?;
            let item = match items.len() {
                0 => return Err(MgmtStoreError::NotFound),
                1 => items.swap_remove(0),
                // Two items of this installation: never guess which is the key.
                _ => return Err(MgmtStoreError::Corrupt),
            };
            if item.is_locked().await.map_err(|e| service_error(&e))? {
                return Err(MgmtStoreError::Unavailable(MgmtStoreAvailability::Locked));
            }
            Ok(Zeroizing::new(
                item.get_secret().await.map_err(|e| service_error(&e))?,
            ))
        })?;
        MgmtKey::from_store_bytes(&secret).map_err(|_| MgmtStoreError::Corrupt)
    }

    fn destroy(&self) -> Result<(), MgmtStoreError> {
        drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let mut items = self.mine(&collection).await?;
            let item = match items.len() {
                0 => return Err(MgmtStoreError::NotFound),
                1 => items.swap_remove(0),
                // Never delete by guess: a duplicate is for the owner to resolve.
                _ => return Err(MgmtStoreError::Corrupt),
            };
            let path = item.item_path.as_str().to_owned();
            item.delete().await.map_err(|e| service_error(&e))?;
            if self
                .mine(&collection)
                .await?
                .iter()
                .any(|i| i.item_path.as_str() == path)
            {
                return Err(MgmtStoreError::Failed);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-level and pure checks only: no Secret Service exists on a build host, and
    /// the owner's collection is never touched by a test. The scope names the
    /// application and the installation, and the kind is the product kind.
    #[test]
    fn scope_names_the_application_and_the_installation() {
        let environment = EnvironmentId::from_random_bytes([6; 16]);
        let store = LinuxSecretServiceMgmt::new(&environment);
        assert_eq!(
            store.kind(),
            MgmtStoreKind::Product(StoreKind::LinuxSecretService)
        );
        let scope = store.scope();
        assert_eq!(scope.get(ATTR_APPLICATION), Some(&"heimdall-mgmt"));
        assert_eq!(scope.get(ATTR_ENVIRONMENT), Some(&environment.as_str()));
        assert_eq!(store.label, item_label(&environment));
    }
}
