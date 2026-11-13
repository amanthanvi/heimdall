//! ⟨ADR-0008 §17.27 item 10; wave-5 security review, release deletion-gate probe⟩ The
//! release-profile deletion gate of `heimdall_issuer::retire::delete_awaiting`, as a
//! permanent integration test of `heimdall-issuer` (target `integration_issuer_release_gate`).
//!
//! A test-configuration store kind (`SecretStoreKind::Test`, the testkit's scratch store in
//! the CLI's tests) is deleted by exact locator in a **debug** build only (§17.25 item 7
//! (d)). In a **release** build (`cargo test --release -p heimdall-issuer --test
//! integration_issuer_release_gate`) the same call refuses the test kind **before any store
//! I/O**: no `list`, no `get`, no `delete`, and every item stays. Each profile runs its own
//! assertions, so the target never runs zero tests in either.
//!
//! The store is an in-memory test kind that counts every call; no platform store, keychain
//! or file is touched.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::sync::Mutex;

use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::StoreKind;
use heimdall_issuer::retire::{RetireError, TEST_STORE_DELETION, delete_awaiting};
use heimdall_issuer::store::{
    SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef, StoredCaKey,
};

/// The store calls a deletion attempt made.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Calls {
    list: usize,
    get: usize,
    delete: usize,
}

/// An in-memory test-kind store that counts its calls.
#[derive(Default)]
struct CountingTestStore {
    items: Mutex<Vec<StoreItemRef>>,
    calls: Mutex<Calls>,
}

impl CountingTestStore {
    fn calls(&self) -> Calls {
        *self.calls.lock().unwrap()
    }

    fn reset(&self) {
        *self.calls.lock().unwrap() = Calls::default();
    }

    fn items(&self) -> Vec<StoreItemRef> {
        self.items.lock().unwrap().clone()
    }
}

impl SecretStore for CountingTestStore {
    fn kind(&self) -> SecretStoreKind {
        SecretStoreKind::Test("release_gate")
    }

    fn availability(&self) -> StoreAvailability {
        StoreAvailability::Available
    }

    fn put(&self, fp: &CaFingerprint, _key: &StoredCaKey) -> Result<StoreItemRef, StoreError> {
        let item = StoreItemRef {
            kind: self.kind(),
            fingerprint: fp.clone(),
            locator: format!("release-gate/{}", fp.as_str()),
        };
        self.items.lock().unwrap().push(item.clone());
        Ok(item)
    }

    fn get(&self, _fp: &CaFingerprint) -> Result<StoredCaKey, StoreError> {
        self.calls.lock().unwrap().get += 1;
        Err(StoreError::NotFound)
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        self.calls.lock().unwrap().delete += 1;
        let mut items = self.items.lock().unwrap();
        let before = items.len();
        items.retain(|i| i != item);
        if items.len() == before {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
        self.calls.lock().unwrap().list += 1;
        Ok(self.items())
    }
}

/// The gate's switch is the build profile itself.
#[test]
fn test_store_deletion_follows_the_build_profile() {
    assert_eq!(TEST_STORE_DELETION, cfg!(debug_assertions));
}

/// A test-kind store item, named by its exact recorded locator: a release build refuses
/// it before any store I/O and keeps every item; a debug build deletes exactly it.
#[test]
fn release_build_never_deletes_a_test_kind_store_item() {
    let store = CountingTestStore::default();
    let (k1, k2) = (
        StoredCaKey::generate().unwrap(),
        StoredCaKey::generate().unwrap(),
    );
    let (f1, f2) = (k1.fingerprint().unwrap(), k2.fingerprint().unwrap());
    let i1 = store.put(&f1, &k1).unwrap();
    let i2 = store.put(&f2, &k2).unwrap();
    store.reset();
    let got = delete_awaiting(&store, &f1, StoreKind::MacosLoginKeychain, &i1.locator);
    #[cfg(not(debug_assertions))]
    {
        assert_eq!(got, Err(RetireError::LocatorMismatch));
        assert_eq!(
            store.calls(),
            Calls::default(),
            "refused before any store I/O"
        );
        assert_eq!(store.items(), vec![i1, i2], "every item stays");
    }
    #[cfg(debug_assertions)]
    {
        assert_eq!(got, Ok(()));
        assert_eq!(store.items(), vec![i2], "exactly the recorded item went");
        let calls = store.calls();
        assert_eq!(calls.delete, 1, "{calls:?}");
        assert!(calls.list >= 1, "re-read after the deletion: {calls:?}");
    }
}

/// In either profile a test-kind item under another CA's locator, or an empty locator, is
/// refused with nothing deleted.
#[test]
fn a_test_kind_item_of_another_ca_is_never_deleted() {
    let store = CountingTestStore::default();
    let (k1, k2) = (
        StoredCaKey::generate().unwrap(),
        StoredCaKey::generate().unwrap(),
    );
    let (f1, f2) = (k1.fingerprint().unwrap(), k2.fingerprint().unwrap());
    let i1 = store.put(&f1, &k1).unwrap();
    let i2 = store.put(&f2, &k2).unwrap();
    for locator in [i2.locator.as_str(), ""] {
        assert_eq!(
            delete_awaiting(&store, &f1, StoreKind::MacosLoginKeychain, locator),
            Err(RetireError::LocatorMismatch),
            "{locator:?}"
        );
    }
    assert_eq!(store.calls().delete, 0);
    assert_eq!(store.items(), vec![i1, i2]);
}
