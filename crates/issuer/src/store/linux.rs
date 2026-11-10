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

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use heimdall_contract::ids::{CaFingerprint, EnvironmentId};
use heimdall_contract::issuer::StoreKind;
use heimdall_credential::cert::SecretCaKey;
use secret_service::{Collection, EncryptionType, SecretService};
use zeroize::Zeroizing;

use super::{
    SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef, item_label,
};

/// The bound on one store operation (connect, negotiate, call).
pub const OPERATION_BOUND: Duration = Duration::from_secs(5);
/// The login collection's object path.
const LOGIN_COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
/// Attribute: the application.
const ATTR_APPLICATION: &str = "heimdall_application";
/// Its value.
const APPLICATION: &str = "heimdall-issuer";
/// Attribute: the CA fingerprint.
const ATTR_FINGERPRINT: &str = "heimdall_ca_fingerprint";
/// Attribute: the environment ID.
const ATTR_ENVIRONMENT: &str = "heimdall_environment_id";
/// The secret's content type.
const CONTENT_TYPE: &str = "application/x-openssh-private-key";

/// The Linux Secret Service K_ca store.
#[derive(Debug, Clone)]
pub struct LinuxSecretService {
    environment: String,
}

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

impl LinuxSecretService {
    /// The store for the installation's `environment`.
    #[must_use]
    pub fn new(environment: &EnvironmentId) -> Self {
        Self {
            environment: environment.as_str().to_owned(),
        }
    }

    fn reference(fingerprint: &CaFingerprint, path: &str) -> StoreItemRef {
        StoreItemRef {
            kind: SecretStoreKind::Product(StoreKind::LinuxSecretService),
            fingerprint: fingerprint.clone(),
            locator: path.to_owned(),
        }
    }
}

impl SecretStore for LinuxSecretService {
    fn kind(&self) -> SecretStoreKind {
        SecretStoreKind::Product(StoreKind::LinuxSecretService)
    }

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

    fn put(
        &self,
        fingerprint: &CaFingerprint,
        key: &SecretCaKey,
    ) -> Result<StoreItemRef, StoreError> {
        if key.fingerprint().map_err(|_| StoreError::Failed)? != *fingerprint {
            return Err(StoreError::Failed);
        }
        let secret = key.to_secret_bytes().map_err(|_| StoreError::Failed)?;
        let fp = fingerprint.as_str().to_owned();
        let label = item_label(fingerprint);
        let environment = self.environment.clone();
        let secret_ref: &[u8] = &secret;
        let path = drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let existing = collection
                .search_items(HashMap::from([
                    (ATTR_APPLICATION, APPLICATION),
                    (ATTR_FINGERPRINT, fp.as_str()),
                ]))
                .await
                .map_err(|e| service_error(&e))?;
            if !existing.is_empty() {
                return Err(StoreError::AlreadyExists);
            }
            let item = collection
                .create_item(
                    &label,
                    HashMap::from([
                        (ATTR_APPLICATION, APPLICATION),
                        (ATTR_FINGERPRINT, fp.as_str()),
                        (ATTR_ENVIRONMENT, environment.as_str()),
                    ]),
                    secret_ref,
                    false,
                    CONTENT_TYPE,
                )
                .await
                .map_err(|e| service_error(&e))?;
            Ok(item.item_path.as_str().to_owned())
        })?;
        drop(secret);
        Ok(Self::reference(fingerprint, &path))
    }

    fn get(&self, fingerprint: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
        let fp = fingerprint.as_str().to_owned();
        let secret = drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let mut items = collection
                .search_items(HashMap::from([
                    (ATTR_APPLICATION, APPLICATION),
                    (ATTR_FINGERPRINT, fp.as_str()),
                ]))
                .await
                .map_err(|e| service_error(&e))?;
            let item = match items.len() {
                0 => return Err(StoreError::NotFound),
                1 => items.swap_remove(0),
                _ => return Err(StoreError::Corrupt),
            };
            if item.is_locked().await.map_err(|e| service_error(&e))? {
                return Err(StoreError::Unavailable(StoreAvailability::Locked));
            }
            let secret = Zeroizing::new(item.get_secret().await.map_err(|e| service_error(&e))?);
            Ok(secret)
        })?;
        let key = SecretCaKey::from_secret_bytes(&secret).map_err(|_| StoreError::Corrupt)?;
        if key.fingerprint().map_err(|_| StoreError::Corrupt)? != *fingerprint {
            return Err(StoreError::Corrupt);
        }
        Ok(key)
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        if item.kind != self.kind() {
            return Err(StoreError::Failed);
        }
        let fp = item.fingerprint.as_str().to_owned();
        let locator = item.locator.clone();
        drive(move || async move {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let attrs = HashMap::from([
                (ATTR_APPLICATION, APPLICATION),
                (ATTR_FINGERPRINT, fp.as_str()),
            ]);
            let items = collection
                .search_items(attrs.clone())
                .await
                .map_err(|e| service_error(&e))?;
            let Some(found) = items.iter().find(|i| i.item_path.as_str() == locator) else {
                return Err(StoreError::NotFound);
            };
            found.delete().await.map_err(|e| service_error(&e))?;
            let after = collection
                .search_items(attrs)
                .await
                .map_err(|e| service_error(&e))?;
            if after.iter().any(|i| i.item_path.as_str() == locator) {
                return Err(StoreError::Failed);
            }
            Ok(())
        })
    }

    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
        let found = drive(|| async {
            let service = connect().await?;
            let collection = unlocked_login(&service).await?;
            let items = collection
                .search_items(HashMap::from([(ATTR_APPLICATION, APPLICATION)]))
                .await
                .map_err(|e| service_error(&e))?;
            let mut out = Vec::new();
            for item in &items {
                let attrs = item.get_attributes().await.map_err(|e| service_error(&e))?;
                if let Some(fp) = attrs.get(ATTR_FINGERPRINT) {
                    out.push((fp.clone(), item.item_path.as_str().to_owned()));
                }
            }
            Ok(out)
        })?;
        let mut items: Vec<StoreItemRef> = found
            .iter()
            .filter_map(|(fp, path)| {
                CaFingerprint::parse(fp)
                    .ok()
                    .map(|f| Self::reference(&f, path))
            })
            .collect();
        items.sort_by(|a, b| a.fingerprint.as_str().cmp(b.fingerprint.as_str()));
        Ok(items)
    }
}
