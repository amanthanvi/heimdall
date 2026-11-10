//! The environment-scoped logic of an attribute-addressed K_ca store (the Secret Service
//! model; ADR-0008 D1, §17.17 item 3; wave-1 review W1-R01).
//!
//! Items live in one store the OS user shares across every Heimdall installation (the
//! login collection). Each item carries the attributes `heimdall_application =
//! heimdall-issuer`, `heimdall_ca_fingerprint` and `heimdall_environment_id`, and
//! **every** lookup here is scoped to this installation's environment: duplicate
//! detection in `put`, `get`, `delete` and `list`. So two installations holding the
//! same (restored) CA keep two items, each installation sees and deletes only its own,
//! and `get` is never `Corrupt` merely because another installation holds the CA.
//!
//! The logic is platform-neutral and generic over [`AttributeBackend`], so a test can run
//! it against an in-memory shared store on any host; on Linux the backend is the Secret
//! Service (`store::linux`).

use heimdall_contract::ids::{CaFingerprint, EnvironmentId};
use heimdall_credential::cert::SecretCaKey;
use zeroize::Zeroizing;

use super::{
    SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef, item_label,
};

/// Attribute: the application.
pub const ATTR_APPLICATION: &str = "heimdall_application";
/// Its value.
pub const APPLICATION: &str = "heimdall-issuer";
/// Attribute: the CA fingerprint.
pub const ATTR_FINGERPRINT: &str = "heimdall_ca_fingerprint";
/// Attribute: the environment ID (the installation).
pub const ATTR_ENVIRONMENT: &str = "heimdall_environment_id";

/// One item a search found: its exact identity and the two attributes this logic reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrItem {
    /// The item's exact identity in the backend (the Secret Service object path).
    pub path: String,
    /// `heimdall_ca_fingerprint`, when present.
    pub fingerprint: Option<String>,
    /// `heimdall_environment_id`, when present.
    pub environment: Option<String>,
}

/// An attribute-addressed secret store (the Secret Service operations this logic uses).
/// Every call is bounded and never prompts.
pub trait AttributeBackend: Send + Sync {
    /// Whether the store can be read without interaction.
    fn availability(&self) -> StoreAvailability;

    /// The items whose attributes include every pair of `attributes`.
    ///
    /// # Errors
    /// [`StoreError`].
    fn search(&self, attributes: &[(&str, &str)]) -> Result<Vec<AttrItem>, StoreError>;

    /// Create an item; returns its path.
    ///
    /// # Errors
    /// [`StoreError`].
    fn create(
        &self,
        label: &str,
        attributes: &[(&str, &str)],
        secret: &[u8],
    ) -> Result<String, StoreError>;

    /// The secret of the item at `path` among those matching `attributes`
    /// ([`StoreError::NotFound`] when it is not among them).
    ///
    /// # Errors
    /// [`StoreError`].
    fn secret(
        &self,
        attributes: &[(&str, &str)],
        path: &str,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError>;

    /// Delete the item at `path` among those matching `attributes`
    /// ([`StoreError::NotFound`] when it is not among them).
    ///
    /// # Errors
    /// [`StoreError`].
    fn delete(&self, attributes: &[(&str, &str)], path: &str) -> Result<(), StoreError>;
}

/// The environment-scoped K_ca store over an [`AttributeBackend`] (module docs).
#[derive(Debug)]
pub struct AttributeStore<B> {
    backend: B,
    environment: String,
    kind: SecretStoreKind,
}

impl<B: AttributeBackend> AttributeStore<B> {
    /// The store of the installation `environment` over `backend`, reporting `kind`.
    #[must_use]
    pub fn new(backend: B, environment: &EnvironmentId, kind: SecretStoreKind) -> Self {
        Self {
            backend,
            environment: environment.as_str().to_owned(),
            kind,
        }
    }

    /// The environment this store's items belong to.
    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }

    /// The backend.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn scope<'a>(&'a self, fingerprint: &'a str) -> [(&'a str, &'a str); 3] {
        [
            (ATTR_APPLICATION, APPLICATION),
            (ATTR_FINGERPRINT, fingerprint),
            (ATTR_ENVIRONMENT, self.environment.as_str()),
        ]
    }

    /// This installation's items for `fingerprint`: searched with the environment in
    /// the attributes, then checked again on what the backend reported (fail closed if
    /// a backend ignored an attribute).
    fn mine(&self, fingerprint: &CaFingerprint) -> Result<Vec<AttrItem>, StoreError> {
        let fp = fingerprint.as_str();
        Ok(self
            .backend
            .search(&self.scope(fp))?
            .into_iter()
            .filter(|i| {
                i.fingerprint.as_deref() == Some(fp)
                    && i.environment.as_deref() == Some(self.environment.as_str())
            })
            .collect())
    }

    fn reference(&self, fingerprint: &CaFingerprint, path: &str) -> StoreItemRef {
        StoreItemRef {
            kind: self.kind,
            fingerprint: fingerprint.clone(),
            locator: path.to_owned(),
        }
    }
}

impl<B: AttributeBackend> SecretStore for AttributeStore<B> {
    fn kind(&self) -> SecretStoreKind {
        self.kind
    }

    fn availability(&self) -> StoreAvailability {
        self.backend.availability()
    }

    fn put(
        &self,
        fingerprint: &CaFingerprint,
        key: &SecretCaKey,
    ) -> Result<StoreItemRef, StoreError> {
        if key.fingerprint().map_err(|_| StoreError::Failed)? != *fingerprint {
            return Err(StoreError::Failed);
        }
        if !self.mine(fingerprint)?.is_empty() {
            return Err(StoreError::AlreadyExists);
        }
        let secret = key.to_secret_bytes().map_err(|_| StoreError::Failed)?;
        let path = self.backend.create(
            &item_label(fingerprint),
            &self.scope(fingerprint.as_str()),
            &secret,
        )?;
        Ok(self.reference(fingerprint, &path))
    }

    fn get(&self, fingerprint: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
        let mut items = self.mine(fingerprint)?;
        let item = match items.len() {
            0 => return Err(StoreError::NotFound),
            1 => items.swap_remove(0),
            // Two items of this installation for one CA: never guess.
            _ => return Err(StoreError::Corrupt),
        };
        let secret = self
            .backend
            .secret(&self.scope(fingerprint.as_str()), &item.path)?;
        let key = SecretCaKey::from_secret_bytes(&secret).map_err(|_| StoreError::Corrupt)?;
        if key.fingerprint().map_err(|_| StoreError::Corrupt)? != *fingerprint {
            return Err(StoreError::Corrupt);
        }
        Ok(key)
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        if item.kind != self.kind {
            return Err(StoreError::Failed);
        }
        // Only an item of this installation, by its exact identity.
        if !self
            .mine(&item.fingerprint)?
            .iter()
            .any(|i| i.path == item.locator)
        {
            return Err(StoreError::NotFound);
        }
        self.backend
            .delete(&self.scope(item.fingerprint.as_str()), &item.locator)?;
        if self
            .mine(&item.fingerprint)?
            .iter()
            .any(|i| i.path == item.locator)
        {
            return Err(StoreError::Failed);
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
        let found = self.backend.search(&[
            (ATTR_APPLICATION, APPLICATION),
            (ATTR_ENVIRONMENT, self.environment.as_str()),
        ])?;
        let mut items: Vec<StoreItemRef> = found
            .iter()
            .filter(|i| i.environment.as_deref() == Some(self.environment.as_str()))
            .filter_map(|i| {
                let fp = CaFingerprint::parse(i.fingerprint.as_deref()?).ok()?;
                Some(self.reference(&fp, &i.path))
            })
            .collect();
        items.sort_by(|a, b| {
            a.fingerprint
                .as_str()
                .cmp(b.fingerprint.as_str())
                .then_with(|| a.locator.cmp(&b.locator))
        });
        Ok(items)
    }
}
