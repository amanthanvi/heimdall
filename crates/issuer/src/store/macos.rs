//! `MacosLoginKeychain` (ADR-0008 D1; m03-plan U4): K_ca as a generic-password item
//! in the login keychain, labelled and serviced `heimdall-issuer/<fingerprint>`, its
//! account the environment ID, its access list (SecAccess) trusting **only** this
//! executable. Every keychain call runs with keychain user interaction disabled
//! (`SecKeychainSetUserInteractionAllowed(false)`, process-wide, so this module
//! serializes its calls), so the issuer never triggers a prompt: `errSecInteractionNotAllowed` (and `errSecAuthFailed`, which a locked
//! keychain returns to such a read) is [`StoreAvailability::InteractionNotAllowed`]
//! (`issuer_store_locked`).
//!
//! **Test configuration only** (`debug_assertions`, the M01 `testcfg` pattern): the
//! store can point at a disposable **file** keychain created by path in a test's
//! scratch directory ([`MacosLoginKeychain::create_disposable_file_keychain`]), never
//! added to the search list, never made the default, and deleted by path
//! ([`MacosLoginKeychain::delete_disposable_file_keychain`]). That run is mechanism
//! evidence only: a release build cannot select it, so it can never produce a
//! product-store claim (ADR-0008 D12 item 3).
//!
//! There is no plaintext fallback: a store that cannot be used is a
//! [`StoreError::Unavailable`], never a file.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use heimdall_contract::ids::{CaFingerprint, EnvironmentId};
use heimdall_contract::issuer::StoreKind;
use heimdall_credential::cert::SecretCaKey;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework::os::macos::keychain::SecKeychain;
use zeroize::Zeroizing;

use super::{
    ITEM_LABEL_PREFIX, SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef,
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
/// keychain returns (observed on Darwin 27.2 against a locked disposable file
/// keychain), and what an access list that would have prompted returns. Either way
/// the read needed the owner, so it is `interaction_not_allowed`.
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

/// The macOS login-keychain K_ca store.
#[derive(Debug, Clone)]
pub struct MacosLoginKeychain {
    path: PathBuf,
    account: String,
}

/// Map a Security framework status to a store error (never item content).
fn status_error(code: i32) -> StoreError {
    match code {
        ERR_ITEM_NOT_FOUND => StoreError::NotFound,
        ERR_DUPLICATE_ITEM => StoreError::AlreadyExists,
        ERR_INTERACTION_NOT_ALLOWED | ERR_AUTH_FAILED | ERR_USER_CANCELED => {
            StoreError::Unavailable(StoreAvailability::InteractionNotAllowed)
        }
        ERR_NO_SUCH_KEYCHAIN | ERR_NO_DEFAULT_KEYCHAIN | ERR_INVALID_KEYCHAIN => {
            StoreError::Unavailable(StoreAvailability::Missing)
        }
        _ => StoreError::Failed,
    }
}

impl MacosLoginKeychain {
    /// The login keychain of the account whose home is `account_home` (the account
    /// database's home, as `localenv::sys::account_home` reads it; never `$HOME`).
    #[must_use]
    pub fn login(account_home: &Path, environment: &EnvironmentId) -> Self {
        Self {
            path: account_home.join(LOGIN_KEYCHAIN),
            account: environment.as_str().to_owned(),
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
        }
    }

    /// **Test configuration only**: create a disposable file keychain at `path`
    /// (which must not exist), protected by `password` (passed in memory, never in
    /// an argument), with no lock timeout and no lock on sleep. `SecKeychainCreate`
    /// by path: the keychain is not added to the search list and does not become the
    /// default.
    ///
    /// # Errors
    /// [`StoreError::AlreadyExists`] when `path` exists; [`StoreError::Failed`]
    /// otherwise.
    #[cfg(debug_assertions)]
    pub fn create_disposable_file_keychain(path: &Path, password: &str) -> Result<(), StoreError> {
        use security_framework::os::macos::keychain::{CreateOptions, KeychainSettings};
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(StoreError::AlreadyExists);
        }
        let mut keychain = CreateOptions::new()
            .password(password)
            .create(path)
            .map_err(|_| StoreError::Failed)?;
        keychain
            .set_settings(&KeychainSettings::new())
            .map_err(|_| StoreError::Failed)
    }

    /// **Test configuration only**: lock the disposable file keychain at `path`
    /// (`SecKeychainLock` is reached through `security lock-keychain <path>`, which
    /// takes no secret).
    ///
    /// # Errors
    /// [`StoreError::Failed`].
    #[cfg(debug_assertions)]
    pub fn lock_disposable_file_keychain(path: &Path) -> Result<(), StoreError> {
        let status = std::process::Command::new("/usr/bin/security")
            .arg("lock-keychain")
            .arg(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| StoreError::Failed)?;
        if status.success() {
            Ok(())
        } else {
            Err(StoreError::Failed)
        }
    }

    /// **Test configuration only**: delete the disposable file keychain at `path`
    /// (`SecKeychainDelete` on the keychain opened by that path).
    ///
    /// # Errors
    /// [`StoreError::Failed`].
    #[cfg(debug_assertions)]
    pub fn delete_disposable_file_keychain(path: &Path) -> Result<(), StoreError> {
        let keychain = SecKeychain::open(path).map_err(|_| StoreError::Failed)?;
        sys::delete_keychain(keychain).map_err(|_| StoreError::Failed)
    }

    /// The keychain file this store uses.
    #[must_use]
    pub fn keychain_path(&self) -> &Path {
        &self.path
    }

    fn open(&self) -> Result<SecKeychain, StoreError> {
        SecKeychain::open(&self.path).map_err(|e| status_error(e.code()))
    }

    fn locator(&self, fingerprint: &CaFingerprint) -> String {
        format!(
            "service={};account={}",
            item_label(fingerprint),
            self.account
        )
    }

    /// Read the item's secret. Call only inside [`without_ui`].
    fn read_secret(
        &self,
        keychain: &SecKeychain,
        fingerprint: &CaFingerprint,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let (password, _item) = keychain
            .find_generic_password(&item_label(fingerprint), &self.account)
            .map_err(|e| status_error(e.code()))?;
        let secret = Zeroizing::new(password.to_vec());
        drop(password);
        Ok(secret)
    }
}

/// Serializes this module's keychain calls: `SecKeychainSetUserInteractionAllowed` is
/// process-wide, so one call's guard must not re-enable interaction under another's.
static NO_UI: Mutex<()> = Mutex::new(());

/// Run `f` with keychain user interaction disabled (no keychain call here can show a
/// prompt), one at a time in this process.
fn without_ui<T>(f: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
    let _serial = NO_UI.lock().unwrap_or_else(PoisonError::into_inner);
    let _guard = SecKeychain::disable_user_interaction().map_err(|_| StoreError::Failed)?;
    f()
}

impl SecretStore for MacosLoginKeychain {
    fn kind(&self) -> SecretStoreKind {
        SecretStoreKind::Product(StoreKind::MacosLoginKeychain)
    }

    fn availability(&self) -> StoreAvailability {
        let keychain = match self.open() {
            Ok(k) => k,
            Err(StoreError::Unavailable(a)) => return a,
            Err(_) => return StoreAvailability::Missing,
        };
        match sys::keychain_status(&keychain) {
            Ok(bits) if bits & sys::UNLOCK_STATE_STATUS != 0 => StoreAvailability::Available,
            Ok(_) => StoreAvailability::Locked,
            Err(code) => match status_error(code) {
                StoreError::Unavailable(a) => a,
                _ => StoreAvailability::Missing,
            },
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
        match self.availability() {
            StoreAvailability::Available => {}
            other => return Err(StoreError::Unavailable(other)),
        }
        let keychain = self.open()?;
        let secret = key.to_secret_bytes().map_err(|_| StoreError::Failed)?;
        let label = item_label(fingerprint);
        without_ui(|| {
            match self.read_secret(&keychain, fingerprint) {
                Ok(_) => return Err(StoreError::AlreadyExists),
                Err(StoreError::NotFound) => {}
                Err(e) => return Err(e),
            }
            sys::add_generic_password_trusting_self(
                &keychain,
                &label,
                &self.account,
                &label,
                &secret,
            )
            .map_err(status_error)
        })?;
        Ok(StoreItemRef {
            kind: self.kind(),
            fingerprint: fingerprint.clone(),
            locator: self.locator(fingerprint),
        })
    }

    fn get(&self, fingerprint: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
        let keychain = self.open()?;
        let secret = without_ui(|| self.read_secret(&keychain, fingerprint))?;
        let key = SecretCaKey::from_secret_bytes(&secret).map_err(|_| StoreError::Corrupt)?;
        if key.fingerprint().map_err(|_| StoreError::Corrupt)? != *fingerprint {
            return Err(StoreError::Corrupt);
        }
        Ok(key)
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        if item.kind != self.kind() || item.locator != self.locator(&item.fingerprint) {
            return Err(StoreError::Failed);
        }
        let keychain = self.open()?;
        let label = item_label(&item.fingerprint);
        without_ui(|| {
            let (password, found) = keychain
                .find_generic_password(&label, &self.account)
                .map_err(|e| status_error(e.code()))?;
            drop(password);
            found.delete();
            match self.read_secret(&keychain, &item.fingerprint) {
                Err(StoreError::NotFound) => Ok(()),
                Ok(_) => Err(StoreError::Failed),
                Err(e) => Err(e),
            }
        })
    }

    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
        let keychain = self.open()?;
        let results = without_ui(|| {
            match ItemSearchOptions::new()
                .class(ItemClass::generic_password())
                .keychains(std::slice::from_ref(&keychain))
                .load_attributes(true)
                .limit(Limit::All)
                .search()
            {
                Ok(r) => Ok(r),
                Err(e) if e.code() == ERR_ITEM_NOT_FOUND => Ok(Vec::new()),
                Err(e) => Err(status_error(e.code())),
            }
        })?;
        let mut items = Vec::new();
        for result in &results {
            let SearchResult::Dict(_) = result else {
                continue;
            };
            let Some(attrs) = result.simplify_dict() else {
                continue;
            };
            let (Some(service), Some(account)) = (attrs.get("svce"), attrs.get("acct")) else {
                continue;
            };
            let Some(fp) = service
                .strip_prefix(ITEM_LABEL_PREFIX)
                .and_then(|f| CaFingerprint::parse(f).ok())
            else {
                continue;
            };
            items.push(StoreItemRef {
                kind: self.kind(),
                fingerprint: fp,
                locator: format!("service={service};account={account}"),
            });
        }
        items.sort_by(|a, b| a.fingerprint.as_str().cmp(b.fingerprint.as_str()));
        Ok(items)
    }
}
