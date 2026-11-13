//! `MacosLoginKeychain` (ADR-0008 D1; m03-plan U4): K_ca as a generic-password item
//! in the login keychain, labelled and serviced `heimdall-issuer/<fingerprint>`, its
//! account the environment ID, its access list (SecAccess) trusting **only** this
//! executable. Every keychain call runs with keychain user interaction disabled
//! (`SecKeychainSetUserInteractionAllowed(false)`, process-wide, so this module
//! serializes its calls), so the issuer never triggers a prompt: `errSecInteractionNotAllowed` (and `errSecAuthFailed`, which a locked
//! keychain returns to such a read) is [`StoreAvailability::InteractionNotAllowed`]
//! (`issuer_store_locked`).
//!
//! ⟨ADR-0008 §17.28 item 6⟩ `errSecAuthFailed` from an item read while the keychain is
//! **unlocked** is the item's access list denying this executable (it trusts the creating
//! executable's code identity, and an ad-hoc-signed build's identity is its exact code
//! hash, so an update or rebuild loses it): [`StoreAvailability::AccessDenied`]
//! (`issuer_store_access_denied`), never the lock ([`read_status_error`]).
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
/// keychain), and what an access list that does not trust this executable returns
/// from an **unlocked** one (observed in wave 5, round 3). A read tells them apart by
/// the keychain's lock status ([`read_status_error`]); any other call maps it to
/// `interaction_not_allowed`.
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
        sys::ERR_CS_REQ_FAILED => StoreError::ExecutableChanged,
        _ => StoreError::Failed,
    }
}

/// ⟨ADR-0008 §17.28 item 6⟩ Map an item **read**'s status, given whether the keychain was
/// unlocked when the read failed (`None`: its status could not be read).
/// `errSecAuthFailed` from an unlocked keychain is the access list denying this
/// executable ([`StoreAvailability::AccessDenied`]); from a locked keychain, or one whose
/// status is unknown, it stays the lock ([`StoreAvailability::InteractionNotAllowed`]).
/// Every other status maps as [`status_error`] does (`errSecInteractionNotAllowed` is the
/// lock, whatever the status reads).
fn read_status_error(code: i32, unlocked: Option<bool>) -> StoreError {
    match (code, unlocked) {
        (ERR_AUTH_FAILED, Some(true)) => StoreError::Unavailable(StoreAvailability::AccessDenied),
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
fn read_error(keychain: &SecKeychain, code: i32) -> StoreError {
    let unlocked = if code == ERR_AUTH_FAILED {
        unlocked_now(keychain)
    } else {
        None
    };
    read_status_error(code, unlocked)
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
        locator_of(fingerprint, &self.account)
    }

    /// ⟨§17.28 item 7⟩ The account `item` names, when it is an item of this installation
    /// for its CA: the base account or a restore generation of it (never another
    /// installation's account, never another service).
    fn account_of(&self, item: &StoreItemRef) -> Option<String> {
        let rest = item
            .locator
            .strip_prefix("service=")?
            .strip_prefix(item_label(&item.fingerprint).as_str())?;
        let account = rest.strip_prefix(";account=")?;
        generation_of(&self.account, account).map(|_| account.to_owned())
    }

    /// Read the secret of `fingerprint`'s item under `account`. Call only inside
    /// [`without_ui`].
    fn read_secret(
        &self,
        keychain: &SecKeychain,
        fingerprint: &CaFingerprint,
        account: &str,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let (password, _item) = keychain
            .find_generic_password(&item_label(fingerprint), account)
            .map_err(|e| read_error(keychain, e.code()))?;
        let secret = Zeroizing::new(password.to_vec());
        drop(password);
        Ok(secret)
    }
}

/// ⟨ADR-0008 §17.28 item 7⟩ The highest restore generation (`<environment>#r<n>`); a
/// restore that finds every generation used is refused.
pub const MAX_RESTORE_GENERATION: u32 = 99;

/// An item's locator: its service (the label) and account.
fn locator_of(fingerprint: &CaFingerprint, account: &str) -> String {
    format!("service={};account={account}", item_label(fingerprint))
}

/// ⟨ADR-0008 §17.28 item 7⟩ The account of restore generation `n` of `base` (`0`: `base`
/// itself; else `<base>#r<n>`). Environment IDs contain no `#`, so a generation account
/// never equals another installation's base account.
fn generation_account(base: &str, n: u32) -> String {
    if n == 0 {
        base.to_owned()
    } else {
        format!("{base}#r{n}")
    }
}

/// The restore generation `account` is of `base` (`Some(0)` for `base`), or `None` when
/// it is not one of this installation's accounts (canonical form only: no leading zero,
/// `1..=MAX_RESTORE_GENERATION`).
fn generation_of(base: &str, account: &str) -> Option<u32> {
    if account == base {
        return Some(0);
    }
    let digits = account.strip_prefix(base)?.strip_prefix("#r")?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u32 = digits.parse().ok()?;
    (1..=MAX_RESTORE_GENERATION).contains(&n).then_some(n)
}

/// The lowest restore generation not in `used`, or `None` when every one is.
fn lowest_free_generation(used: &[u32]) -> Option<u32> {
    (1..=MAX_RESTORE_GENERATION).find(|n| !used.contains(n))
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
            match self.read_secret(&keychain, fingerprint, &self.account) {
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
        let secret = without_ui(|| self.read_secret(&keychain, fingerprint, &self.account))?;
        decode(&secret, fingerprint)
    }

    fn get_item(&self, item: &StoreItemRef) -> Result<SecretCaKey, StoreError> {
        if item.kind != self.kind() {
            return Err(StoreError::NotFound);
        }
        let Some(account) = self.account_of(item) else {
            return Err(StoreError::NotFound);
        };
        let keychain = self.open()?;
        let secret = without_ui(|| self.read_secret(&keychain, &item.fingerprint, &account))?;
        decode(&secret, &item.fingerprint)
    }

    /// ⟨ADR-0008 §17.28 item 7⟩ The same service, account `<environment>#r<n>` with the
    /// lowest `n` no item of this installation uses (existence read from attributes only,
    /// so an unreadable item still counts); the add itself never overwrites
    /// (`errSecDuplicateItem` is [`StoreError::AlreadyExists`]).
    fn put_new_item(
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
        let used: Vec<u32> = self
            .list()?
            .iter()
            .filter(|i| i.fingerprint == *fingerprint)
            .filter_map(|i| self.account_of(i))
            .filter_map(|a| generation_of(&self.account, &a))
            .collect();
        let n = lowest_free_generation(&used).ok_or(StoreError::AlreadyExists)?;
        let account = generation_account(&self.account, n);
        let keychain = self.open()?;
        let secret = key.to_secret_bytes().map_err(|_| StoreError::Failed)?;
        let label = item_label(fingerprint);
        without_ui(|| {
            sys::add_generic_password_trusting_self(&keychain, &label, &account, &label, &secret)
                .map_err(status_error)
        })?;
        Ok(StoreItemRef {
            kind: self.kind(),
            fingerprint: fingerprint.clone(),
            locator: locator_of(fingerprint, &account),
        })
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        if item.kind != self.kind() {
            return Err(StoreError::Failed);
        }
        let Some(account) = self.account_of(item) else {
            return Err(StoreError::Failed);
        };
        let keychain = self.open()?;
        let label = item_label(&item.fingerprint);
        without_ui(|| {
            // The item is read before it is deleted: one this executable cannot read
            // (`issuer_store_access_denied`) is never deleted (§17.28 item 7).
            let (password, found) = keychain
                .find_generic_password(&label, &account)
                .map_err(|e| read_error(&keychain, e.code()))?;
            drop(password);
            found.delete();
            match self.read_secret(&keychain, &item.fingerprint, &account) {
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
            // Only this installation's items (§17.17 item 3; wave-1 review W1-R02): the
            // keychain is shared by every installation of the OS user, and an item of
            // another environment is never listed, adopted or deleted here.
            // ⟨§17.28 item 7⟩ Its restore generations (`<environment>#r<n>`) included.
            if generation_of(&self.account, account).is_none() {
                continue;
            }
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
        items.sort_by(|a, b| {
            (a.fingerprint.as_str(), a.locator.as_str())
                .cmp(&(b.fingerprint.as_str(), b.locator.as_str()))
        });
        Ok(items)
    }
}

/// Decode a read secret as the CA key of `fingerprint` ([`StoreError::Corrupt`] otherwise).
fn decode(secret: &[u8], fingerprint: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
    let key = SecretCaKey::from_secret_bytes(secret).map_err(|_| StoreError::Corrupt)?;
    if key.fingerprint().map_err(|_| StoreError::Corrupt)? != *fingerprint {
        return Err(StoreError::Corrupt);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⟨ADR-0008 §17.28 item 7⟩ Restore-generation accounts: canonical `<base>#r<n>` only,
    /// never another installation's account, and the lowest free generation.
    #[test]
    fn restore_generation_accounts() {
        let base = "env_AAAA";
        assert_eq!(generation_account(base, 0), base);
        assert_eq!(generation_account(base, 3), "env_AAAA#r3");
        assert_eq!(generation_of(base, base), Some(0));
        assert_eq!(generation_of(base, "env_AAAA#r1"), Some(1));
        assert_eq!(generation_of(base, "env_AAAA#r99"), Some(99));
        for other in [
            "env_AAAA#r0",
            "env_AAAA#r01",
            "env_AAAA#r100",
            "env_AAAA#r",
            "env_AAAA#rx",
            "env_AAAAB",
            "env_BBBB#r1",
            "",
        ] {
            assert_eq!(generation_of(base, other), None, "{other}");
        }
        assert_eq!(lowest_free_generation(&[]), Some(1));
        assert_eq!(lowest_free_generation(&[0, 1, 3]), Some(2));
        let all: Vec<u32> = (0..=MAX_RESTORE_GENERATION).collect();
        assert_eq!(lowest_free_generation(&all), None);
    }

    /// ⟨ADR-0008 §17.28 item 6⟩ The read mapping: an access-list denial
    /// (`errSecAuthFailed` from an unlocked keychain) is `access_denied`; the same status
    /// from a locked keychain, or one whose status is unknown, and
    /// `errSecInteractionNotAllowed` whatever the status, stay the lock.
    #[test]
    fn read_status_mapping_tells_access_denial_from_the_lock() {
        assert_eq!(
            read_status_error(ERR_AUTH_FAILED, Some(true)),
            StoreError::Unavailable(StoreAvailability::AccessDenied)
        );
        for unlocked in [Some(false), None] {
            assert_eq!(
                read_status_error(ERR_AUTH_FAILED, unlocked),
                StoreError::Unavailable(StoreAvailability::InteractionNotAllowed)
            );
        }
        for unlocked in [Some(true), Some(false), None] {
            assert_eq!(
                read_status_error(ERR_INTERACTION_NOT_ALLOWED, unlocked),
                StoreError::Unavailable(StoreAvailability::InteractionNotAllowed)
            );
            assert_eq!(
                read_status_error(ERR_ITEM_NOT_FOUND, unlocked),
                StoreError::NotFound
            );
            assert_eq!(
                read_status_error(sys::ERR_CS_REQ_FAILED, unlocked),
                StoreError::ExecutableChanged
            );
        }
        // Outside a read, errSecAuthFailed keeps its lock meaning.
        assert_eq!(
            status_error(ERR_AUTH_FAILED),
            StoreError::Unavailable(StoreAvailability::InteractionNotAllowed)
        );
    }
}
