//! `LinuxSecretService` (ADR-0008 D1; m03-plan U4; wave-0 D-Q1: secret-service
//! 5.2.0): K_ca as an item of the **login** collection
//! (`/org/freedesktop/secrets/collection/login`), read over a **DH-encrypted
//! session** (`EncryptionType::Dh`), labelled `heimdall-issuer/<fingerprint>` with the
//! attributes `heimdall_application = heimdall-issuer`, `heimdall_ca_fingerprint` and
//! `heimdall_environment_id`.
//!
//! **Driving the async client from the synchronous trait.** Each operation builds a
//! current-thread tokio runtime (I/O and time) on a scoped thread of its own, runs the
//! whole exchange (connect, session negotiation, the call) inside one
//! `tokio::time::timeout` of [`OPERATION_BOUND`], then drops the runtime, which
//! cancels zbus's tasks. The thread keeps it safe to call from inside another
//! runtime (the CLI's) without nesting; the bound keeps a stuck bus or a provider
//! prompt from blocking the issuer's request loop. secret-service's own blocking API
//! is not used: it runs on zbus's process-global multi-thread runtime, which has no
//! per-call bound and panics if it cannot be built.
//!
//! The issuer never triggers a prompt: no call here unlocks anything
//! (`unlock`/`ensure_unlocked` are never used); a locked collection or item is
//! [`StoreAvailability::Locked`]. There is no plaintext fallback.
//!
//! **Scoped to the installation** (ADR-0008 §17.17 item 3; wave-1 review W1-R01): the
//! store logic is `store::attributes::AttributeStore`, whose every lookup carries
//! `heimdall_environment_id`, over [`SecretServiceBackend`]. Two installations of the
//! same OS user holding the same CA keep two items, and each sees, reads and deletes
//! only its own.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use heimdall_contract::ids::{CaFingerprint, EnvironmentId};
use heimdall_contract::issuer::StoreKind;
use heimdall_credential::cert::SecretCaKey;
use secret_service::{Collection, EncryptionType, SecretService};
use zeroize::Zeroizing;

use super::attributes::{
    ATTR_ENVIRONMENT, ATTR_FINGERPRINT, AttrItem, AttributeBackend, AttributeStore,
};
use super::{SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef};

/// The bound on one store operation (connect, negotiate, call).
pub const OPERATION_BOUND: Duration = Duration::from_secs(5);
/// The login collection's object path.
const LOGIN_COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
/// The secret's content type.
const CONTENT_TYPE: &str = "application/x-openssh-private-key";

fn service_error(e: &secret_service::Error) -> StoreError {
    match e {
        secret_service::Error::Locked => StoreError::Unavailable(StoreAvailability::Locked),
        secret_service::Error::Prompt | secret_service::Error::PromptDisconnected => {
            StoreError::Unavailable(StoreAvailability::InteractionNotAllowed)
        }
        secret_service::Error::Unavailable
        | secret_service::Error::Zbus(_)
        | secret_service::Error::ZbusFdo(_) => StoreError::Unavailable(StoreAvailability::Missing),
        secret_service::Error::Crypto(_) | secret_service::Error::Zvariant(_) => {
            StoreError::Unavailable(StoreAvailability::Corrupt)
        }
        _ => StoreError::Failed,
    }
}

/// Run `make()`'s future on a current-thread runtime of its own, on a scoped
/// thread, bounded by [`OPERATION_BOUND`] (module docs).
fn drive<T, F, Fut>(make: F) -> Result<T, StoreError>
where
    T: Send,
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<T, StoreError>>,
{
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| StoreError::Unavailable(StoreAvailability::Missing))?;
                runtime.block_on(async move {
                    match tokio::time::timeout(OPERATION_BOUND, make()).await {
                        Ok(result) => result,
                        Err(_) => Err(StoreError::Unavailable(StoreAvailability::Missing)),
                    }
                })
            })
            .join()
            .unwrap_or(Err(StoreError::Failed))
    })
}

async fn connect() -> Result<SecretService<'static>, StoreError> {
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|e| service_error(&e))
}

async fn login<'a>(service: &'a SecretService<'a>) -> Result<Collection<'a>, StoreError> {
    let collections = service
        .get_all_collections()
        .await
        .map_err(|e| service_error(&e))?;
    collections
        .into_iter()
        .find(|c| c.collection_path.as_str() == LOGIN_COLLECTION)
        .ok_or(StoreError::Unavailable(StoreAvailability::Missing))
}

async fn unlocked_login<'a>(service: &'a SecretService<'a>) -> Result<Collection<'a>, StoreError> {
    let collection = login(service).await?;
    if collection
        .is_locked()
        .await
        .map_err(|e| service_error(&e))?
    {
        return Err(StoreError::Unavailable(StoreAvailability::Locked));
    }
    Ok(collection)
}

fn owned(attributes: &[(&str, &str)]) -> Vec<(String, String)> {
    attributes
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn as_map(attributes: &[(String, String)]) -> HashMap<&str, &str> {
    attributes
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// The Secret Service as an [`AttributeBackend`]: the login collection over a DH
/// session, one bounded connection per call (module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct SecretServiceBackend;

impl AttributeBackend for SecretServiceBackend {
    fn availability(&self) -> StoreAvailability {
        let result = drive(|| async {
            let service = connect().await?;
            unlocked_login(&service).await.map(|_| ())
        });
        match result {
            Ok(()) => StoreAvailability::Available,
            Err(StoreError::Unavailable(a)) => a,
            Err(_) => StoreAvailability::Missing,
        }
    }

    fn search(&self, attributes: &[(&str, &str)]) -> Result<Vec<AttrItem>, StoreError> {
        let attributes = owned(attributes);
        drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let items = collection
                .search_items(as_map(&attributes))
                .await
                .map_err(|e| service_error(&e))?;
            let mut out = Vec::new();
            for item in &items {
                let attrs = item.get_attributes().await.map_err(|e| service_error(&e))?;
                out.push(AttrItem {
                    path: item.item_path.as_str().to_owned(),
                    fingerprint: attrs.get(ATTR_FINGERPRINT).cloned(),
                    environment: attrs.get(ATTR_ENVIRONMENT).cloned(),
                });
            }
            Ok(out)
        })
    }

    fn create(
        &self,
        label: &str,
        attributes: &[(&str, &str)],
        secret: &[u8],
    ) -> Result<String, StoreError> {
        let attributes = owned(attributes);
        let label = label.to_owned();
        drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let item = collection
                .create_item(&label, as_map(&attributes), secret, false, CONTENT_TYPE)
                .await
                .map_err(|e| service_error(&e))?;
            Ok(item.item_path.as_str().to_owned())
        })
    }

    fn secret(
        &self,
        attributes: &[(&str, &str)],
        path: &str,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let attributes = owned(attributes);
        let path = path.to_owned();
        drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let items = collection
                .search_items(as_map(&attributes))
                .await
                .map_err(|e| service_error(&e))?;
            let Some(item) = items.iter().find(|i| i.item_path.as_str() == path) else {
                return Err(StoreError::NotFound);
            };
            if item.is_locked().await.map_err(|e| service_error(&e))? {
                return Err(StoreError::Unavailable(StoreAvailability::Locked));
            }
            Ok(Zeroizing::new(
                item.get_secret().await.map_err(|e| service_error(&e))?,
            ))
        })
    }

    fn delete(&self, attributes: &[(&str, &str)], path: &str) -> Result<(), StoreError> {
        let attributes = owned(attributes);
        let path = path.to_owned();
        drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let items = collection
                .search_items(as_map(&attributes))
                .await
                .map_err(|e| service_error(&e))?;
            let Some(found) = items.iter().find(|i| i.item_path.as_str() == path) else {
                return Err(StoreError::NotFound);
            };
            found.delete().await.map_err(|e| service_error(&e))
        })
    }
}

/// The Linux Secret Service K_ca store of one installation.
#[derive(Debug)]
pub struct LinuxSecretService {
    inner: AttributeStore<SecretServiceBackend>,
}

impl LinuxSecretService {
    /// The store for the installation's `environment`.
    #[must_use]
    pub fn new(environment: &EnvironmentId) -> Self {
        Self {
            inner: AttributeStore::new(
                SecretServiceBackend,
                environment,
                SecretStoreKind::Product(StoreKind::LinuxSecretService),
            ),
        }
    }
}

impl SecretStore for LinuxSecretService {
    fn kind(&self) -> SecretStoreKind {
        self.inner.kind()
    }

    fn availability(&self) -> StoreAvailability {
        self.inner.availability()
    }

    fn put(
        &self,
        fingerprint: &CaFingerprint,
        key: &SecretCaKey,
    ) -> Result<StoreItemRef, StoreError> {
        self.inner.put(fingerprint, key)
    }

    fn get(&self, fingerprint: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
        self.inner.get(fingerprint)
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        self.inner.delete(item)
    }

    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
        self.inner.list()
    }
}
