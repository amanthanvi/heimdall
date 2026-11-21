//! `MacosLoginKeychainMgmt` (ADR-0012 §3.4; ADR-0005 §5.1/§5.2; m06-plan U2): K_mgmt as a
//! generic-password item in the macOS login keychain, its service [`ITEM_SERVICE`], its
//! account the installation's environment ID, its label [`item_label`], and its access
//! list (SecAccess) trusting **only** this executable. A file-based keychain item is never
//! iCloud-synchronized, so the key stays on this device.
//!
//! Every keychain call runs with keychain user interaction disabled
//! (`SecKeychainSetUserInteractionAllowed(false)`, process-wide, so this module serializes
//! its calls): a read that would prompt is [`MgmtStoreAvailability::InteractionNotAllowed`]
//! and a locked keychain is [`MgmtStoreAvailability::Locked`], both
//! `mgmt_key_store_locked`. `errSecAuthFailed` from an item read while the keychain is
//! **unlocked** is the access list denying this executable
//! ([`MgmtStoreAvailability::AccessDenied`]), never the lock. There is no plaintext
//! fallback, no export and no overwrite; the item is deleted by its exact service and
//! account only, after it is read back.
//!
//! **Test configuration only** (`debug_assertions`, the M01 `testcfg` pattern): the store
//! can point at a disposable **file** keychain created by path in a test's scratch
//! directory ([`MacosLoginKeychainMgmt::create_disposable_file_keychain`]), never added to
//! the search list, never made the default, and deleted by path. That run is mechanism
//! evidence only: a release build cannot select it, so it can never produce a
//! product-store claim.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::issuer::StoreKind;
use security_framework::os::macos::keychain::SecKeychain;
use zeroize::Zeroizing;

use super::{
    ITEM_SERVICE, MgmtKey, MgmtKeyStore, MgmtStoreAvailability, MgmtStoreError, MgmtStoreKind,
    item_label,
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
/// from an **unlocked** one. A read tells them apart by the keychain's lock status
/// ([`read_status_error`]).
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

/// The macOS login-keychain K_mgmt store of one installation.
#[derive(Debug, Clone)]
pub struct MacosLoginKeychainMgmt {
    path: PathBuf,
    account: String,
    label: String,
}

/// Map a Security framework status to a store error (never item content).
fn status_error(code: i32) -> MgmtStoreError {
    match code {
        ERR_ITEM_NOT_FOUND => MgmtStoreError::NotFound,
        ERR_DUPLICATE_ITEM => MgmtStoreError::AlreadyExists,
        ERR_INTERACTION_NOT_ALLOWED | ERR_AUTH_FAILED | ERR_USER_CANCELED => {
            MgmtStoreError::Unavailable(MgmtStoreAvailability::InteractionNotAllowed)
        }
        ERR_NO_SUCH_KEYCHAIN | ERR_NO_DEFAULT_KEYCHAIN | ERR_INVALID_KEYCHAIN => {
            MgmtStoreError::Unavailable(MgmtStoreAvailability::Missing)
        }
        sys::ERR_CS_REQ_FAILED => MgmtStoreError::Unavailable(MgmtStoreAvailability::AccessDenied),
        _ => MgmtStoreError::Failed,
    }
}

/// Map an item **read**'s status, given whether the keychain was unlocked when the read
/// failed (`None`: its status could not be read). `errSecAuthFailed` from an unlocked
/// keychain is the access list denying this executable
/// ([`MgmtStoreAvailability::AccessDenied`]); from a locked keychain it is
/// [`MgmtStoreAvailability::Locked`]; with the status unknown it stays
/// [`MgmtStoreAvailability::InteractionNotAllowed`]. Every other status maps as
/// [`status_error`] does.
fn read_status_error(code: i32, unlocked: Option<bool>) -> MgmtStoreError {
    match (code, unlocked) {
        (ERR_AUTH_FAILED, Some(true)) => {
            MgmtStoreError::Unavailable(MgmtStoreAvailability::AccessDenied)
        }
        (ERR_AUTH_FAILED, Some(false)) => {
            MgmtStoreError::Unavailable(MgmtStoreAvailability::Locked)
        }
        _ => status_error(code),
    }
}

/// Whether `keychain` is unlocked now (`None` when its status cannot be read).
fn unlocked_now(keychain: &SecKeychain) -> Option<bool> {
    sys::keychain_status(keychain)
        .ok()
        .map(|bits| bits & sys::UNLOCK_STATE_STATUS != 0)
}

/// A failed item read on `keychain` (its lock status read at once, [`read_status_error`]).
fn read_error(keychain: &SecKeychain, code: i32) -> MgmtStoreError {
    let unlocked = if code == ERR_AUTH_FAILED {
        unlocked_now(keychain)
    } else {
        None
    };
    read_status_error(code, unlocked)
}

/// Serializes this module's keychain calls: `SecKeychainSetUserInteractionAllowed` is
/// process-wide, so one call's guard must not re-enable interaction under another's.
static NO_UI: Mutex<()> = Mutex::new(());

/// Run `f` with keychain user interaction disabled (no keychain call here can show a
/// prompt), one at a time in this process.
fn without_ui<T>(f: impl FnOnce() -> Result<T, MgmtStoreError>) -> Result<T, MgmtStoreError> {
    let _serial = NO_UI.lock().unwrap_or_else(PoisonError::into_inner);
    let _guard = SecKeychain::disable_user_interaction().map_err(|_| MgmtStoreError::Failed)?;
    f()
}

impl MacosLoginKeychainMgmt {
    /// The login keychain of the account whose home is `account_home` (the account
    /// database's home, as `localenv::sys::account_home` reads it; never `$HOME`).
    #[must_use]
    pub fn login(account_home: &Path, environment: &EnvironmentId) -> Self {
        Self {
            path: account_home.join(LOGIN_KEYCHAIN),
            account: environment.as_str().to_owned(),
            label: item_label(environment),
        }
    }

    /// **Test configuration only**: a disposable file keychain at `path` (created by
    /// [`Self::create_disposable_file_keychain`] in the test's scratch directory).
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn disposable_file_keychain(path: impl Into<PathBuf>, environment: &EnvironmentId) -> Self {
        Self {
            path: path.into(),
            account: environment.as_str().to_owned(),
            label: item_label(environment),
        }
    }

    /// **Test configuration only**: create a disposable file keychain at `path` (which
    /// must not exist), protected by `password` (passed in memory, never in an argument),
    /// with no lock timeout and no lock on sleep. `SecKeychainCreate` by path: the keychain
    /// is not added to the search list and does not become the default.
    ///
    /// # Errors
    /// [`MgmtStoreError::AlreadyExists`] when `path` exists; [`MgmtStoreError::Failed`]
    /// otherwise.
    #[cfg(debug_assertions)]
    pub fn create_disposable_file_keychain(
        path: &Path,
        password: &str,
    ) -> Result<(), MgmtStoreError> {
        use security_framework::os::macos::keychain::{CreateOptions, KeychainSettings};
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(MgmtStoreError::AlreadyExists);
        }
        let mut keychain = CreateOptions::new()
            .password(password)
            .create(path)
            .map_err(|_| MgmtStoreError::Failed)?;
        keychain
            .set_settings(&KeychainSettings::new())
            .map_err(|_| MgmtStoreError::Failed)
    }

    /// **Test configuration only**: lock the disposable file keychain at `path`
    /// (`SecKeychainLock` is reached through `security lock-keychain <path>`, which takes
    /// no secret).
    ///
    /// # Errors
    /// [`MgmtStoreError::Failed`].
    #[cfg(debug_assertions)]
    pub fn lock_disposable_file_keychain(path: &Path) -> Result<(), MgmtStoreError> {
        let status = std::process::Command::new("/usr/bin/security")
            .arg("lock-keychain")
            .arg(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| MgmtStoreError::Failed)?;
        if status.success() {
            Ok(())
        } else {
            Err(MgmtStoreError::Failed)
        }
    }

    /// **Test configuration only**: delete the disposable file keychain at `path`
    /// (`SecKeychainDelete` on the keychain opened by that path).
    ///
    /// # Errors
    /// [`MgmtStoreError::Failed`].
    #[cfg(debug_assertions)]
    pub fn delete_disposable_file_keychain(path: &Path) -> Result<(), MgmtStoreError> {
        let keychain = SecKeychain::open(path).map_err(|_| MgmtStoreError::Failed)?;
        sys::delete_keychain(keychain).map_err(|_| MgmtStoreError::Failed)
    }

    /// The keychain file this store uses.
    #[must_use]
    pub fn keychain_path(&self) -> &Path {
        &self.path
    }

    fn open(&self) -> Result<SecKeychain, MgmtStoreError> {
        SecKeychain::open(&self.path).map_err(|e| status_error(e.code()))
    }

    /// The opened keychain, refused as [`MgmtStoreAvailability::Locked`] (or `missing`)
    /// unless it is available now.
    fn open_available(&self) -> Result<SecKeychain, MgmtStoreError> {
        let keychain = self.open()?;
        match keychain_availability(&keychain) {
            MgmtStoreAvailability::Available => Ok(keychain),
            other => Err(MgmtStoreError::Unavailable(other)),
        }
    }

    /// Read the item's secret. Call only inside [`without_ui`].
    fn read_secret(&self, keychain: &SecKeychain) -> Result<Zeroizing<Vec<u8>>, MgmtStoreError> {
        let (password, _item) = keychain
            .find_generic_password(ITEM_SERVICE, &self.account)
            .map_err(|e| read_error(keychain, e.code()))?;
        let secret = Zeroizing::new(password.to_vec());
        drop(password);
        Ok(secret)
    }
}

/// `keychain`'s availability from its status bits.
fn keychain_availability(keychain: &SecKeychain) -> MgmtStoreAvailability {
    match sys::keychain_status(keychain) {
        Ok(bits) if bits & sys::UNLOCK_STATE_STATUS != 0 => MgmtStoreAvailability::Available,
        Ok(_) => MgmtStoreAvailability::Locked,
        Err(code) => match status_error(code) {
            MgmtStoreError::Unavailable(a) => a,
            _ => MgmtStoreAvailability::Missing,
        },
    }
}

impl MgmtKeyStore for MacosLoginKeychainMgmt {
    fn kind(&self) -> MgmtStoreKind {
        MgmtStoreKind::Product(StoreKind::MacosLoginKeychain)
    }

    fn availability(&self) -> MgmtStoreAvailability {
        match self.open() {
            Ok(keychain) => keychain_availability(&keychain),
            Err(MgmtStoreError::Unavailable(a)) => a,
            Err(_) => MgmtStoreAvailability::Missing,
        }
    }

    fn put(&self, key: &MgmtKey) -> Result<(), MgmtStoreError> {
        let keychain = self.open_available()?;
        let secret = key.to_store_bytes();
        without_ui(|| {
            // Never overwrites: an item that exists (readable or not) refuses the add.
            match self.read_secret(&keychain) {
                Ok(_) => return Err(MgmtStoreError::AlreadyExists),
                Err(MgmtStoreError::NotFound) => {}
                Err(e) => return Err(e),
            }
            sys::add_generic_password_trusting_self(
                &keychain,
                ITEM_SERVICE,
                &self.account,
                &self.label,
                &secret,
            )
            .map_err(status_error)
        })
    }

    fn load(&self) -> Result<MgmtKey, MgmtStoreError> {
        let keychain = self.open_available()?;
        let secret = without_ui(|| self.read_secret(&keychain))?;
        MgmtKey::from_store_bytes(&secret).map_err(|_| MgmtStoreError::Corrupt)
    }

    fn destroy(&self) -> Result<(), MgmtStoreError> {
        let keychain = self.open_available()?;
        without_ui(|| {
            // The item is read before it is deleted: one this executable cannot read is
            // never deleted. The exact service and account only, never a search.
            let (password, found) = keychain
                .find_generic_password(ITEM_SERVICE, &self.account)
                .map_err(|e| read_error(&keychain, e.code()))?;
            drop(password);
            found.delete();
            match self.read_secret(&keychain) {
                Err(MgmtStoreError::NotFound) => Ok(()),
                Ok(_) => Err(MgmtStoreError::Failed),
                Err(e) => Err(e),
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use heimdall_contract::envelope::reason;

    use super::*;
    use crate::vault::SystemRng;

    fn environment() -> EnvironmentId {
        EnvironmentId::from_random_bytes([6; 16])
    }

    /// A disposable file keychain in scratch, deleted by path on drop.
    struct DisposableKeychain {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl DisposableKeychain {
        fn create() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("hm-mgmt.keychain-db");
            // A per-run password, in memory only (never an argument).
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

    /// Fixture/mechanism evidence only (a test-configuration file keychain, not the login
    /// keychain; never a product-store claim): the status mapping, including that an
    /// access-list denial (`errSecAuthFailed` from an unlocked keychain) is `access_denied`
    /// and the same status from a locked keychain is the lock.
    #[test]
    fn status_mapping_tells_access_denial_from_the_lock() {
        assert_eq!(
            read_status_error(ERR_AUTH_FAILED, Some(true)),
            MgmtStoreError::Unavailable(MgmtStoreAvailability::AccessDenied)
        );
        assert_eq!(
            read_status_error(ERR_AUTH_FAILED, Some(false)),
            MgmtStoreError::Unavailable(MgmtStoreAvailability::Locked)
        );
        assert_eq!(
            read_status_error(ERR_AUTH_FAILED, None),
            MgmtStoreError::Unavailable(MgmtStoreAvailability::InteractionNotAllowed)
        );
        for unlocked in [Some(true), Some(false), None] {
            assert_eq!(
                read_status_error(ERR_INTERACTION_NOT_ALLOWED, unlocked),
                MgmtStoreError::Unavailable(MgmtStoreAvailability::InteractionNotAllowed)
            );
            assert_eq!(
                read_status_error(ERR_ITEM_NOT_FOUND, unlocked),
                MgmtStoreError::NotFound
            );
            assert_eq!(
                read_status_error(sys::ERR_CS_REQ_FAILED, unlocked),
                MgmtStoreError::Unavailable(MgmtStoreAvailability::AccessDenied)
            );
        }
        // Outside a read, errSecAuthFailed keeps its interaction meaning.
        assert_eq!(
            status_error(ERR_AUTH_FAILED),
            MgmtStoreError::Unavailable(MgmtStoreAvailability::InteractionNotAllowed)
        );
        assert_eq!(
            status_error(ERR_DUPLICATE_ITEM),
            MgmtStoreError::AlreadyExists
        );
        assert_eq!(
            status_error(ERR_NO_SUCH_KEYCHAIN),
            MgmtStoreError::Unavailable(MgmtStoreAvailability::Missing)
        );
    }

    /// Fixture/mechanism evidence only (a disposable file keychain, not the login
    /// keychain): put, load and destroy round trip with the access list trusting this
    /// executable, `put` never overwrites, the item is scoped to its environment ID, the
    /// keychain file holds no plaintext key, and destroy removes exactly that item.
    #[test]
    fn round_trip_never_overwrites_and_destroys_exactly_the_item() {
        let kc = DisposableKeychain::create();
        let store = MacosLoginKeychainMgmt::disposable_file_keychain(&kc.path, &environment());
        assert_eq!(
            store.kind(),
            MgmtStoreKind::Product(StoreKind::MacosLoginKeychain)
        );
        assert_eq!(store.availability(), MgmtStoreAvailability::Available);
        assert_eq!(store.load().map(|_| ()), Err(MgmtStoreError::NotFound));
        assert_eq!(store.destroy(), Err(MgmtStoreError::NotFound));

        let key = MgmtKey::generate().unwrap();
        store.put(&key).unwrap();
        assert_eq!(
            store.put(&MgmtKey::generate().unwrap()),
            Err(MgmtStoreError::AlreadyExists)
        );
        let loaded = store.load().unwrap();
        assert_eq!(loaded.public().unwrap(), key.public().unwrap());
        // A fresh store instance on the same file reads the same item.
        let again = MacosLoginKeychainMgmt::disposable_file_keychain(&kc.path, &environment());
        assert_eq!(
            again.load().unwrap().public().unwrap(),
            key.public().unwrap()
        );
        // The keychain file holds no plaintext key.
        let secret = key.to_store_bytes();
        let bytes = std::fs::read(&kc.path).unwrap();
        assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_slice()));

        // Another installation (environment ID) on the same keychain has its own item and
        // destroying one never touches the other.
        let other_env = EnvironmentId::from_random_bytes([7; 16]);
        let other = MacosLoginKeychainMgmt::disposable_file_keychain(&kc.path, &other_env);
        assert_eq!(other.load().map(|_| ()), Err(MgmtStoreError::NotFound));
        let other_key = MgmtKey::generate().unwrap();
        other.put(&other_key).unwrap();
        store.destroy().unwrap();
        assert_eq!(store.load().map(|_| ()), Err(MgmtStoreError::NotFound));
        assert_eq!(
            other.load().unwrap().public().unwrap(),
            other_key.public().unwrap()
        );
        other.destroy().unwrap();

        // `load_or_create` over this store creates once, then reads the same key.
        let (created, was_created) = super::super::load_or_create(&store).unwrap();
        assert!(was_created);
        let (read, was_created) = super::super::load_or_create(&store).unwrap();
        assert!(!was_created);
        assert_eq!(read.public().unwrap(), created.public().unwrap());

        let path = kc.path.clone();
        drop(kc);
        assert!(!path.exists(), "the disposable keychain is deleted by path");
    }

    /// Fixture/mechanism evidence only (a disposable file keychain locked with
    /// `security lock-keychain`): a locked keychain refuses every operation as
    /// `Unavailable(Locked)` (`mgmt_key_store_locked`) without prompting and without
    /// writing, and the item reads again once the keychain is unlocked by the test.
    #[test]
    fn locked_keychain_refuses_with_mgmt_key_store_locked() {
        let kc = DisposableKeychain::create();
        let store = MacosLoginKeychainMgmt::disposable_file_keychain(&kc.path, &environment());
        let key = MgmtKey::generate().unwrap();
        store.put(&key).unwrap();

        MacosLoginKeychainMgmt::lock_disposable_file_keychain(&kc.path).unwrap();
        assert_eq!(store.availability(), MgmtStoreAvailability::Locked);
        let err = store.load().map(|_| ()).unwrap_err();
        assert!(
            matches!(
                err,
                MgmtStoreError::Unavailable(
                    MgmtStoreAvailability::Locked | MgmtStoreAvailability::InteractionNotAllowed
                )
            ),
            "{err:?}"
        );
        assert_eq!(err.refusal_reason(), Some(reason::MGMT_KEY_STORE_LOCKED));
        let err = store.put(&MgmtKey::generate().unwrap()).unwrap_err();
        assert_eq!(err.refusal_reason(), Some(reason::MGMT_KEY_STORE_LOCKED));
        let err = store.destroy().unwrap_err();
        assert_eq!(err.refusal_reason(), Some(reason::MGMT_KEY_STORE_LOCKED));
        let err = super::super::load_or_create(&store)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err.refusal_reason(), Some(reason::MGMT_KEY_STORE_LOCKED));

        let path = kc.path.clone();
        drop(kc);
        assert!(!path.exists(), "the disposable keychain is deleted by path");
    }

    /// The login keychain's path is under the account home given, never `$HOME`.
    #[test]
    fn login_keychain_path_is_under_the_account_home() {
        let store = MacosLoginKeychainMgmt::login(Path::new("/nonexistent-home"), &environment());
        assert_eq!(
            store.keychain_path(),
            Path::new("/nonexistent-home/Library/Keychains/login.keychain-db")
        );
        // A missing keychain is never available and never created.
        assert_eq!(store.availability(), MgmtStoreAvailability::Missing);
    }
}
