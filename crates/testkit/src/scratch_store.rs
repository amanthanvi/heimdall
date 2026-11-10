//! `ScratchSecretStore`: the test-configuration K_ca store (ADR-0008 D1 "Test K_ca";
//! m03-plan U0 "Frozen in wave 0", U4; F23). Feature `managed`.
//!
//! It implements the issuer's frozen [`SecretStore`] trait with the testkit-side kind
//! [`SCRATCH_TEST`], which is **not** a variant of the public `StoreKind`: fixture
//! custody never appears in the public schema and never satisfies a product-store
//! claim (ADR-0008 D12). U4 owns this file and fills the body (the D5 format,
//! encrypted with a per-run passphrase, under the scratch state directory).
//!
//! **Wave 0:** the store reports [`StoreAvailability::Unsupported`] and refuses every
//! operation with [`StoreError::Unavailable`]; it reads and writes nothing.

use std::path::{Path, PathBuf};

use heimdall_contract::ids::CaFingerprint;
use heimdall_credential::cert::SecretCaKey;
use heimdall_issuer::store::{
    SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef,
};

/// The testkit-side store kind name (`scratch_test`; F23).
pub const SCRATCH_TEST: &str = "scratch_test";

/// The scratch K_ca store, rooted at a directory the test run created.
#[derive(Debug)]
pub struct ScratchSecretStore {
    dir: PathBuf,
}

impl ScratchSecretStore {
    /// A store whose items would live under `dir` (the run's scratch state
    /// directory).
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The scratch directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn unavailable() -> StoreError {
        StoreError::Unavailable(StoreAvailability::Unsupported)
    }
}

impl SecretStore for ScratchSecretStore {
    fn kind(&self) -> SecretStoreKind {
        SecretStoreKind::Test(SCRATCH_TEST)
    }

    fn availability(&self) -> StoreAvailability {
        StoreAvailability::Unsupported
    }

    fn put(
        &self,
        fingerprint: &CaFingerprint,
        key: &SecretCaKey,
    ) -> Result<StoreItemRef, StoreError> {
        let _ = (fingerprint, key);
        Err(Self::unavailable())
    }

    fn get(&self, fingerprint: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
        let _ = fingerprint;
        Err(Self::unavailable())
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        let _ = item;
        Err(Self::unavailable())
    }

    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
        Err(Self::unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wave0_scratch_store_is_test_kind_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = ScratchSecretStore::new(dir.path());
        assert_eq!(store.kind(), SecretStoreKind::Test(SCRATCH_TEST));
        assert_eq!(store.kind().product(), None);
        assert_eq!(store.availability(), StoreAvailability::Unsupported);
        let fp = CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap();
        assert_eq!(
            store.get(&fp).err(),
            Some(StoreError::Unavailable(StoreAvailability::Unsupported))
        );
        assert_eq!(
            store.list(),
            Err(StoreError::Unavailable(StoreAvailability::Unsupported))
        );
        let item = StoreItemRef {
            kind: store.kind(),
            fingerprint: fp,
            locator: "x".into(),
        };
        assert_eq!(
            store.delete(&item),
            Err(StoreError::Unavailable(StoreAvailability::Unsupported))
        );
        // Nothing was written into the scratch directory.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
