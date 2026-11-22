//! `MacosLoginKeychainIroh` (ADR-0012 §2.4; m06-plan U56): K_iroh as a generic-password
//! item in the macOS login keychain, one item per endpoint: service [`ITEM_SERVICE`],
//! account `<environment ID>/<endpoint ID>`, label [`item_label`], and an access list
//! (SecAccess) trusting **only** this executable. The login keychain is a file-based
//! keychain, and a file-based keychain item is never iCloud-synchronized: the item is the
//! non-synchronizable, this-device-only item ADR-0012 §2.4 item 2 requires.
//!
//! Every keychain call runs with keychain user interaction disabled
//! (`SecKeychainSetUserInteractionAllowed(false)`, process-wide, so this module serializes
//! its calls): a read that would prompt is [`IrohStoreAvailability::InteractionNotAllowed`]
//! and a locked keychain is [`IrohStoreAvailability::Locked`]. `errSecAuthFailed` from an
//! item read while the keychain is **unlocked** is the access list denying this executable
//! ([`IrohStoreAvailability::AccessDenied`]), never the lock. There is no plaintext
//! fallback, no export and no overwrite; an item is deleted by its exact service and
//! account only, after it is read.
//!
//! **Test configuration only** (`debug_assertions`): the store can point at a disposable
//! **file** keychain created by path in a test's scratch directory
//! ([`MacosLoginKeychainIroh::disposable_file_keychain`], with the keychain made by
//! `crate::mgmt::macos::MacosLoginKeychainMgmt::create_disposable_file_keychain`), never
//! added to the search list, never made the default, and deleted by path. That run is
//! mechanism evidence only: a release build cannot select it, so it can never produce a
//! product-store claim.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use heimdall_contract::ids::{EnvironmentId, IrohEndpointId};
use heimdall_contract::issuer::StoreKind;
use security_framework::os::macos::keychain::SecKeychain;
use zeroize::Zeroizing;

use super::{
    ITEM_SERVICE, IrohKeyMaterial, IrohKeyStore, IrohStoreAvailability, IrohStoreError,
    IrohStoreKind, item_label,
};
use crate::sys::macos as sys;

/// `errSecItemNotFound`.
const ERR_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecDuplicateItem`.
const ERR_DUPLICATE_ITEM: i32 = -25299;
/// `errSecInteractionNotAllowed`.
const ERR_INTERACTION_NOT_ALLOWED: i32 = -25308;
/// `errSecAuthFailed`: with user interaction disabled, what a read of a **locked**
/// keychain returns, and what an access list that does not trust this executable returns
/// from an **unlocked** one ([`read_status_error`] tells them apart).
const ERR_AUTH_FAILED: i32 = -25293;
/// `errSecNoSuchKeychain`.
const ERR_NO_SUCH_KEYCHAIN: i32 = -25294;
/// `errSecNoDefaultKeychain`.
const ERR_NO_DEFAULT_KEYCHAIN: i32 = -25307;
/// `errSecInvalidKeychain`.
const ERR_INVALID_KEYCHAIN: i32 = -25295;
/// `userCanceledErr`.
const ERR_USER_CANCELED: i32 = -128;

/// The login keychain's file under an account home.
const LOGIN_KEYCHAIN: &str = "Library/Keychains/login.keychain-db";

/// Map a Security framework status to a store error (never item content).
fn status_error(code: i32) -> IrohStoreError {
    match code {
        ERR_ITEM_NOT_FOUND => IrohStoreError::NotFound,
        ERR_DUPLICATE_ITEM => IrohStoreError::AlreadyExists,
        ERR_INTERACTION_NOT_ALLOWED | ERR_AUTH_FAILED | ERR_USER_CANCELED => {
            IrohStoreError::Unavailable(IrohStoreAvailability::InteractionNotAllowed)
        }
        ERR_NO_SUCH_KEYCHAIN | ERR_NO_DEFAULT_KEYCHAIN | ERR_INVALID_KEYCHAIN => {
            IrohStoreError::Unavailable(IrohStoreAvailability::Missing)
        }
        sys::ERR_CS_REQ_FAILED => IrohStoreError::Unavailable(IrohStoreAvailability::AccessDenied),
        _ => IrohStoreError::Failed,
    }
}

/// Map an item **read**'s status, given whether the keychain was unlocked when the read
/// failed (`None`: its status could not be read): `errSecAuthFailed` from an unlocked
/// keychain is [`IrohStoreAvailability::AccessDenied`], from a locked one
/// [`IrohStoreAvailability::Locked`], with the status unknown
/// [`IrohStoreAvailability::InteractionNotAllowed`]. Every other status maps as
/// [`status_error`] does.
fn read_status_error(code: i32, unlocked: Option<bool>) -> IrohStoreError {
    match (code, unlocked) {
        (ERR_AUTH_FAILED, Some(true)) => {
            IrohStoreError::Unavailable(IrohStoreAvailability::AccessDenied)
        }
        (ERR_AUTH_FAILED, Some(false)) => {
            IrohStoreError::Unavailable(IrohStoreAvailability::Locked)
        }
        _ => status_error(code),
    }
}

/// A failed item read on `keychain` (its lock status read at once, [`read_status_error`]).
fn read_error(keychain: &SecKeychain, code: i32) -> IrohStoreError {
    let unlocked = if code == ERR_AUTH_FAILED {
        sys::keychain_status(keychain)
            .ok()
            .map(|bits| bits & sys::UNLOCK_STATE_STATUS != 0)
    } else {
        None
    };
    read_status_error(code, unlocked)
}

/// Serializes this module's keychain calls: `SecKeychainSetUserInteractionAllowed` is
/// process-wide, so one call's guard must not re-enable interaction under another's.
static NO_UI: Mutex<()> = Mutex::new(());

/// Run `f` with keychain user interaction disabled, one at a time in this module.
fn without_ui<T>(f: impl FnOnce() -> Result<T, IrohStoreError>) -> Result<T, IrohStoreError> {
    let _serial = NO_UI.lock().unwrap_or_else(PoisonError::into_inner);
    let _guard = SecKeychain::disable_user_interaction().map_err(|_| IrohStoreError::Failed)?;
    f()
}

/// `keychain`'s availability from its status bits.
fn keychain_availability(keychain: &SecKeychain) -> IrohStoreAvailability {
    match sys::keychain_status(keychain) {
        Ok(bits) if bits & sys::UNLOCK_STATE_STATUS != 0 => IrohStoreAvailability::Available,
        Ok(_) => IrohStoreAvailability::Locked,
        Err(code) => match status_error(code) {
            IrohStoreError::Unavailable(a) => a,
            _ => IrohStoreAvailability::Missing,
        },
    }
}

/// The macOS login-keychain K_iroh store of one installation.
#[derive(Debug, Clone)]
pub struct MacosLoginKeychainIroh {
    path: PathBuf,
    environment: EnvironmentId,
}

impl MacosLoginKeychainIroh {
    /// The login keychain of the account whose home is `account_home` (the account
    /// database's home; never `$HOME`).
    #[must_use]
    pub fn login(account_home: &Path, environment: &EnvironmentId) -> Self {
        Self {
            path: account_home.join(LOGIN_KEYCHAIN),
            environment: environment.clone(),
        }
    }

    /// **Test configuration only**: a disposable file keychain at `path` (created by
    /// `MacosLoginKeychainMgmt::create_disposable_file_keychain` in the test's scratch
    /// directory).
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn disposable_file_keychain(path: impl Into<PathBuf>, environment: &EnvironmentId) -> Self {
        Self {
            path: path.into(),
            environment: environment.clone(),
        }
    }

    /// The keychain file this store uses.
    #[must_use]
    pub fn keychain_path(&self) -> &Path {
        &self.path
    }

    /// The item's account: `<environment ID>/<endpoint ID>`.
    fn account(&self, endpoint: &IrohEndpointId) -> String {
        format!("{}/{}", self.environment.as_str(), endpoint.as_str())
    }

    fn open(&self) -> Result<SecKeychain, IrohStoreError> {
        SecKeychain::open(&self.path).map_err(|e| status_error(e.code()))
    }

    /// The opened keychain, refused (`locked`, `missing`) unless it is available now.
    fn open_available(&self) -> Result<SecKeychain, IrohStoreError> {
        let keychain = self.open()?;
        match keychain_availability(&keychain) {
            IrohStoreAvailability::Available => Ok(keychain),
            other => Err(IrohStoreError::Unavailable(other)),
        }
    }

    /// Read `account`'s secret. Call only inside [`without_ui`].
    fn read_secret(
        keychain: &SecKeychain,
        account: &str,
    ) -> Result<Zeroizing<Vec<u8>>, IrohStoreError> {
        let (password, _item) = keychain
            .find_generic_password(ITEM_SERVICE, account)
            .map_err(|e| read_error(keychain, e.code()))?;
        let secret = Zeroizing::new(password.to_vec());
        drop(password);
        Ok(secret)
    }
}

impl IrohKeyStore for MacosLoginKeychainIroh {
    fn kind(&self) -> IrohStoreKind {
        IrohStoreKind::Product(StoreKind::MacosLoginKeychain)
    }

    fn availability(&self) -> IrohStoreAvailability {
        match self.open() {
            Ok(keychain) => keychain_availability(&keychain),
            Err(IrohStoreError::Unavailable(a)) => a,
            Err(_) => IrohStoreAvailability::Missing,
        }
    }

    fn store_ref(&self, endpoint: &IrohEndpointId) -> String {
        item_label(&self.environment, endpoint)
    }

    fn put(&self, endpoint: &IrohEndpointId, key: &IrohKeyMaterial) -> Result<(), IrohStoreError> {
        key.check_endpoint(endpoint)?;
        let keychain = self.open_available()?;
        let account = self.account(endpoint);
        let label = item_label(&self.environment, endpoint);
        let secret = key.to_store_bytes();
        without_ui(|| {
            // Never overwrites: an item that exists (readable or not) refuses the add.
            match Self::read_secret(&keychain, &account) {
                Ok(_) => return Err(IrohStoreError::AlreadyExists),
                Err(IrohStoreError::NotFound) => {}
                Err(e) => return Err(e),
            }
            sys::add_generic_password_trusting_self(
                &keychain,
                ITEM_SERVICE,
                &account,
                &label,
                &secret,
            )
            .map_err(status_error)
        })
    }

    fn load(&self, endpoint: &IrohEndpointId) -> Result<IrohKeyMaterial, IrohStoreError> {
        let keychain = self.open_available()?;
        let account = self.account(endpoint);
        let secret = without_ui(|| Self::read_secret(&keychain, &account))?;
        IrohKeyMaterial::from_store_bytes(&secret, endpoint)
    }

    fn destroy(&self, endpoint: &IrohEndpointId) -> Result<(), IrohStoreError> {
        let keychain = self.open_available()?;
        let account = self.account(endpoint);
        without_ui(|| {
            // The item is read before it is deleted: one this executable cannot read is
            // never deleted. The exact service and account only, never a search.
            let (password, found) = keychain
                .find_generic_password(ITEM_SERVICE, &account)
                .map_err(|e| read_error(&keychain, e.code()))?;
            drop(password);
            found.delete();
            match Self::read_secret(&keychain, &account) {
                Err(IrohStoreError::NotFound) => Ok(()),
                Ok(_) => Err(IrohStoreError::Failed),
                Err(e) => Err(e),
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::iroh::create_key;
    use crate::mgmt::macos::MacosLoginKeychainMgmt;
    use crate::vault::SystemRng;

    fn environment() -> EnvironmentId {
        EnvironmentId::from_random_bytes([6; 16])
    }

    /// A disposable file keychain in scratch with a per-run random password held in
    /// memory only, deleted by path on drop (the K_mgmt test helpers create, lock and
    /// delete it).
    struct DisposableKeychain {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl DisposableKeychain {
        fn create() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("hm-iroh.keychain-db");
            let mut raw = [0u8; 16];
            SystemRng::fill(&mut raw).unwrap();
            let password: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            MacosLoginKeychainMgmt::create_disposable_file_keychain(&path, &password).unwrap();
            Self { _dir: dir, path }
        }
    }

    impl Drop for DisposableKeychain {
        fn drop(&mut self) {
            let _ = MacosLoginKeychainMgmt::delete_disposable_file_keychain(&self.path);
        }
    }

    /// Mechanism evidence only (a disposable file keychain, not the login keychain; never
    /// a product-store claim): `create_key` and put/load/destroy round trip with the access
    /// list trusting this executable, `put` never overwrites, two endpoints (and another
    /// installation) keep independent items, the keychain file holds no plaintext key,
    /// destroy removes exactly that item, and the keychain is deleted by path afterwards.
    #[test]
    fn iroh_macos_disposable_keychain_round_trip_never_overwrites_independent_items() {
        let kc = DisposableKeychain::create();
        let store = MacosLoginKeychainIroh::disposable_file_keychain(&kc.path, &environment());
        assert_eq!(
            store.kind(),
            IrohStoreKind::Product(StoreKind::MacosLoginKeychain)
        );
        assert_eq!(store.kind().column(), "keychain");
        assert_eq!(store.availability(), IrohStoreAvailability::Available);

        let key = IrohKeyMaterial::generate().unwrap();
        let endpoint = key.endpoint_id();
        assert_eq!(
            store.store_ref(&endpoint),
            format!("heimdall-iroh/{}/{endpoint}", environment().as_str())
        );
        assert_eq!(
            store.load(&endpoint).map(|_| ()),
            Err(IrohStoreError::NotFound)
        );
        assert_eq!(store.destroy(&endpoint), Err(IrohStoreError::NotFound));
        store.put(&endpoint, &key).unwrap();
        assert_eq!(
            store.put(&endpoint, &IrohKeyMaterial::from_bytes(*key.expose())),
            Err(IrohStoreError::AlreadyExists)
        );
        assert_eq!(store.load(&endpoint).unwrap().expose(), key.expose());
        // A key under another endpoint's ID is refused before the keychain is touched.
        let stranger = IrohKeyMaterial::generate().unwrap();
        assert_eq!(
            store.put(&endpoint, &stranger),
            Err(IrohStoreError::Corrupt)
        );

        // A second endpoint (create_key) keeps its own item.
        let second = create_key(&store).unwrap();
        assert_ne!(second, endpoint);
        let second_key = store.load(&second).unwrap();
        assert_eq!(second_key.endpoint_id(), second);
        // A fresh store instance on the same file reads the same items.
        let again = MacosLoginKeychainIroh::disposable_file_keychain(&kc.path, &environment());
        assert_eq!(again.load(&endpoint).unwrap().expose(), key.expose());
        // Another installation on the same keychain sees neither.
        let other_env = EnvironmentId::from_random_bytes([7; 16]);
        let other = MacosLoginKeychainIroh::disposable_file_keychain(&kc.path, &other_env);
        assert_eq!(
            other.load(&endpoint).map(|_| ()),
            Err(IrohStoreError::NotFound)
        );

        // The keychain file holds no plaintext key (neither the seed nor the encoding).
        let bytes = std::fs::read(&kc.path).unwrap();
        for secret in [key.to_store_bytes(), second_key.to_store_bytes()] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_slice()));
            let seed = &secret[secret.len() - 32..];
            assert!(!bytes.windows(seed.len()).any(|w| w == seed));
        }

        // Destroy removes exactly that item.
        store.destroy(&endpoint).unwrap();
        assert_eq!(
            store.load(&endpoint).map(|_| ()),
            Err(IrohStoreError::NotFound)
        );
        assert_eq!(store.destroy(&endpoint), Err(IrohStoreError::NotFound));
        assert_eq!(store.load(&second).unwrap().expose(), second_key.expose());
        store.destroy(&second).unwrap();

        let path = kc.path.clone();
        drop(kc);
        assert!(!path.exists(), "the disposable keychain is deleted by path");
    }

    /// Mechanism evidence only (a disposable file keychain locked with
    /// `security lock-keychain`): a locked keychain refuses every operation, with reason
    /// `transport_key_store_unavailable`, without prompting and without writing;
    /// `create_key` generates nothing; the doctor finding reports the lock.
    #[test]
    fn iroh_macos_locked_keychain_refuses() {
        let kc = DisposableKeychain::create();
        let store = MacosLoginKeychainIroh::disposable_file_keychain(&kc.path, &environment());
        let endpoint = create_key(&store).unwrap();

        MacosLoginKeychainMgmt::lock_disposable_file_keychain(&kc.path).unwrap();
        assert_eq!(store.availability(), IrohStoreAvailability::Locked);
        let key = IrohKeyMaterial::generate().unwrap();
        let errors = [
            store.load(&endpoint).map(|_| ()).unwrap_err(),
            store.put(&key.endpoint_id(), &key).unwrap_err(),
            store.destroy(&endpoint).unwrap_err(),
            create_key(&store).map(|_| ()).unwrap_err(),
        ];
        for err in errors {
            assert!(
                matches!(
                    err,
                    IrohStoreError::Unavailable(
                        IrohStoreAvailability::Locked
                            | IrohStoreAvailability::InteractionNotAllowed
                    )
                ),
                "{err:?}"
            );
            assert_eq!(err.reason(), "transport_key_store_unavailable");
        }
        let finding = crate::iroh::doctor_finding(&store).unwrap();
        assert_eq!(finding.detail, "locked");

        let path = kc.path.clone();
        drop(kc);
        assert!(!path.exists(), "the disposable keychain is deleted by path");
    }

    /// The status mapping tells an access-list denial from the lock (pure).
    #[test]
    fn iroh_macos_status_mapping() {
        assert_eq!(
            read_status_error(ERR_AUTH_FAILED, Some(true)),
            IrohStoreError::Unavailable(IrohStoreAvailability::AccessDenied)
        );
        assert_eq!(
            read_status_error(ERR_AUTH_FAILED, Some(false)),
            IrohStoreError::Unavailable(IrohStoreAvailability::Locked)
        );
        assert_eq!(
            read_status_error(ERR_AUTH_FAILED, None),
            IrohStoreError::Unavailable(IrohStoreAvailability::InteractionNotAllowed)
        );
        assert_eq!(
            status_error(ERR_DUPLICATE_ITEM),
            IrohStoreError::AlreadyExists
        );
        assert_eq!(
            status_error(ERR_NO_SUCH_KEYCHAIN),
            IrohStoreError::Unavailable(IrohStoreAvailability::Missing)
        );
    }

    /// The login keychain's path is under the account home given, never `$HOME`; a
    /// missing keychain is `missing` and is never created.
    #[test]
    fn iroh_macos_login_keychain_path_is_under_the_account_home() {
        let store = MacosLoginKeychainIroh::login(Path::new("/nonexistent-home"), &environment());
        assert_eq!(
            store.keychain_path(),
            Path::new("/nonexistent-home/Library/Keychains/login.keychain-db")
        );
        assert_eq!(store.availability(), IrohStoreAvailability::Missing);
        assert!(!store.keychain_path().exists());
    }
}
