//! ⟨M06 U56⟩ K_iroh custody (ADR-0012 §2.4, §2.5, §2.7; m06-plan U56).
//!
//! * **The class** (§2.4 item 1): K_iroh is the Iroh endpoint secret, a reachability key
//!   distinct from every SSH and management credential. Its 32 bytes are an Ed25519 seed
//!   ([`IrohKeyMaterial`]); its public half, as 64 lowercase hex characters, is the
//!   endpoint ID ([`IrohKeyMaterial::endpoint_id`]), which grants nothing (spec §8.6).
//! * **Storage** (§2.4 item 2): only in a verified platform store ([`IrohKeyStore`]): the
//!   macOS login keychain (a generic-password item in a file-based keychain, never
//!   iCloud-synchronized: a non-synchronizable, this-device-only item), Windows DPAPI for
//!   the current user in the local, non-roaming application data, or the Secret Service
//!   login collection. **Never** a plaintext or owner-only file (spec §7.3).
//! * **No verified store** (§2.4 item 3, §2.7): headless Linux, WSL, a container or another
//!   OS has none ([`IrohStoreAvailability::Missing`] or
//!   [`IrohStoreAvailability::Unsupported`]), and a persistent Iroh endpoint is unavailable
//!   for both serving and dialing: `CAPABILITY_UNAVAILABLE` /
//!   `transport_key_store_unavailable` ([`IrohStoreError::reason`]) and a doctor finding
//!   ([`doctor_finding`]). There is no encrypted headless store in V1 (§2.7) and no
//!   plaintext fallback.
//! * **Lifecycle** (§2.4 item 4, §2.5): generated at enable ([`create_key`]), one item per
//!   endpoint so a rotation creates a new item beside the old one, destroyed at disable or
//!   after a rotation ([`IrohKeyStore::destroy`], exactly that item). A locked store makes
//!   the endpoint unavailable while locked.
//! * **Items** are named by [`ITEM_SERVICE`], the installation's environment ID and the
//!   endpoint ID ([`item_label`]); the `transport_keys` row stores the item's locator
//!   ([`IrohKeyStore::store_ref`]) and the store's column name
//!   ([`IrohStoreKind::column`]), never the key.
//!
//! [`IrohKeyMaterial`] cannot be cloned or serialized, and its `Debug` prints no bytes:
//!
//! ```
//! let key = heimdall_credential::iroh::IrohKeyMaterial::from_bytes([7u8; 32]);
//! assert_eq!(format!("{key:?}"), "IrohKeyMaterial(..)");
//! ```
//! ```compile_fail,E0277
//! fn needs<T: Clone>() {}
//! needs::<heimdall_credential::iroh::IrohKeyMaterial>();
//! ```
//! ```compile_fail,E0277
//! fn needs<T: serde::Serialize>() {}
//! needs::<heimdall_credential::iroh::IrohKeyMaterial>();
//! ```
//!
//! **Test stores** ([`FixtureIrohStore`], [`UnsupportedIrohStore`]) report an
//! [`IrohStoreKind::Test`] kind: fixture custody is mechanism evidence only and never
//! satisfies a product-store claim. Tests never touch the owner's keychain, Secret Service
//! or DPAPI items.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{EnvironmentId, IrohEndpointId};
use heimdall_contract::issuer::StoreKind;
use ssh_key::private::Ed25519Keypair;
use zeroize::Zeroizing;

use crate::vault::SystemRng;

// The product stores (ADR-0012 §2.4 item 2).
#[cfg(target_os = "linux")]
#[path = "iroh_linux.rs"]
pub mod linux;
#[cfg(target_os = "macos")]
#[path = "iroh_macos.rs"]
pub mod macos;
#[cfg(windows)]
#[path = "iroh_windows.rs"]
pub mod windows;

/// The keychain service, Secret Service application attribute and DPAPI directory name of
/// every K_iroh item.
pub const ITEM_SERVICE: &str = "heimdall-iroh";

/// The label (and store locator) of the K_iroh item of installation `environment` and
/// endpoint `endpoint`: `heimdall-iroh/<environment>/<endpoint>`.
#[must_use]
pub fn item_label(environment: &EnvironmentId, endpoint: &IrohEndpointId) -> String {
    format!(
        "{ITEM_SERVICE}/{}/{}",
        environment.as_str(),
        endpoint.as_str()
    )
}

/// The fixed prefix of a stored K_iroh secret (then the 32-byte Ed25519 seed), so an item
/// that is not one of ours reads as corrupt rather than as a key.
const SECRET_MAGIC: &[u8] = b"heimdall-iroh/1 ed25519\0";

/// The Ed25519 seed length.
const SEED_BYTES: usize = 32;

/// K_iroh's 32 secret bytes (an Ed25519 seed). Zeroized on drop; no `Clone`, `Serialize`
/// or `Deserialize`; `Debug` prints `IrohKeyMaterial(..)`.
pub struct IrohKeyMaterial(Zeroizing<[u8; SEED_BYTES]>);

impl std::fmt::Debug for IrohKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IrohKeyMaterial(..)")
    }
}

impl IrohKeyMaterial {
    /// Wrap 32 secret bytes (an Ed25519 seed).
    #[must_use]
    pub fn from_bytes(bytes: [u8; SEED_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The 32 secret bytes, for the transport to build its endpoint key from (and nowhere
    /// else).
    #[must_use]
    pub fn expose(&self) -> &[u8; SEED_BYTES] {
        &self.0
    }

    /// A new K_iroh from the OS CSPRNG.
    ///
    /// # Errors
    /// [`IrohStoreError::Failed`] when the CSPRNG fails (no key is made).
    pub fn generate() -> Result<Self, IrohStoreError> {
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        SystemRng::fill(seed.as_mut_slice()).map_err(|_| IrohStoreError::Failed)?;
        Ok(Self(seed))
    }

    /// The endpoint ID: the Ed25519 public key derived from the seed, as 64 lowercase hex
    /// characters (what iroh's `SecretKey::from_bytes(seed).public()` displays).
    #[must_use]
    pub fn endpoint_id(&self) -> IrohEndpointId {
        let public = Ed25519Keypair::from_seed(&self.0).public;
        let hex = hex_lower(public.as_ref());
        match IrohEndpointId::parse(&hex) {
            Ok(id) => id,
            // 32 bytes always encode as 64 lowercase hex characters.
            Err(_) => unreachable!("a 32-byte public key is 64 lowercase hex characters"),
        }
    }

    /// The store encoding (magic, then the seed), for an [`IrohKeyStore`] implementation
    /// to write into its platform store and nowhere else.
    fn to_store_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(SECRET_MAGIC.len() + SEED_BYTES));
        out.extend_from_slice(SECRET_MAGIC);
        out.extend_from_slice(self.0.as_slice());
        out
    }

    /// Decode [`Self::to_store_bytes`]'s encoding of the key of `endpoint`:
    /// [`IrohStoreError::Corrupt`] when the bytes do not decode or the derived endpoint ID
    /// differs.
    fn from_store_bytes(bytes: &[u8], endpoint: &IrohEndpointId) -> Result<Self, IrohStoreError> {
        let seed = bytes
            .strip_prefix(SECRET_MAGIC)
            .filter(|s| s.len() == SEED_BYTES)
            .ok_or(IrohStoreError::Corrupt)?;
        let mut out = Zeroizing::new([0u8; SEED_BYTES]);
        out.copy_from_slice(seed);
        let key = Self(out);
        key.check_endpoint(endpoint)?;
        Ok(key)
    }

    /// [`IrohStoreError::Corrupt`] unless this key's endpoint ID is `endpoint`.
    fn check_endpoint(&self, endpoint: &IrohEndpointId) -> Result<(), IrohStoreError> {
        if self.endpoint_id() == *endpoint {
            Ok(())
        } else {
            Err(IrohStoreError::Corrupt)
        }
    }
}

/// Lowercase hex of `bytes`.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// The kind of an [`IrohKeyStore`]: a product store (the public `StoreKind` names), or a
/// test store named by the test (never a product claim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IrohStoreKind {
    /// A product platform store.
    Product(StoreKind),
    /// A test store (fixture custody: mechanism evidence only).
    Test(&'static str),
}

impl IrohStoreKind {
    /// The `transport_keys.store_kind` column: `keychain` (the macOS Keychain), `dpapi`,
    /// `secret_service`, or the test store's name. A product kind this crate has no store
    /// for is `unsupported`.
    #[must_use]
    pub fn column(&self) -> &'static str {
        match *self {
            IrohStoreKind::Product(
                StoreKind::MacosLoginKeychain | StoreKind::MacosDataProtectionKeychain,
            ) => "keychain",
            IrohStoreKind::Product(StoreKind::WindowsDpapi) => "dpapi",
            IrohStoreKind::Product(StoreKind::LinuxSecretService) => "secret_service",
            IrohStoreKind::Product(_) => "unsupported",
            IrohStoreKind::Test(name) => name,
        }
    }

    /// The product kind, when this is one.
    #[must_use]
    pub fn product(self) -> Option<StoreKind> {
        match self {
            IrohStoreKind::Product(kind) => Some(kind),
            IrohStoreKind::Test(_) => None,
        }
    }
}

/// A K_iroh store's availability. Anything but [`IrohStoreAvailability::Available`] makes
/// the persistent Iroh endpoint unavailable (`transport_key_store_unavailable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IrohStoreAvailability {
    /// The store can be read without interaction.
    Available,
    /// The store is locked.
    Locked,
    /// A read would need user interaction, which is never allowed.
    InteractionNotAllowed,
    /// The store (or its service) is absent: headless Linux, WSL, a container.
    Missing,
    /// The store answered with data that does not decode.
    Corrupt,
    /// No verified persistent store exists on this OS.
    Unsupported,
    /// The store is unlocked but the item's access list does not trust this executable.
    AccessDenied,
}

impl IrohStoreAvailability {
    /// The wire name (also the doctor detail).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            IrohStoreAvailability::Available => "available",
            IrohStoreAvailability::Locked => "locked",
            IrohStoreAvailability::InteractionNotAllowed => "interaction_not_allowed",
            IrohStoreAvailability::Missing => "missing",
            IrohStoreAvailability::Corrupt => "corrupt",
            IrohStoreAvailability::Unsupported => "unsupported",
            IrohStoreAvailability::AccessDenied => "access_denied",
        }
    }
}

/// A K_iroh store operation's failure. Messages carry no key material or item content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum IrohStoreError {
    /// The store is not available.
    #[error("the transport key store is unavailable ({})", .0.as_str())]
    Unavailable(IrohStoreAvailability),
    /// No K_iroh item exists for this endpoint.
    #[error("no transport key is stored for this endpoint")]
    NotFound,
    /// A K_iroh item already exists for this endpoint (`put` never overwrites).
    #[error("a transport key is already stored for this endpoint")]
    AlreadyExists,
    /// The item does not decode, or its key is not this endpoint's.
    #[error("the stored transport key is corrupt")]
    Corrupt,
    /// The store refused the operation for another reason, or the CSPRNG failed.
    #[error("the transport key store refused the operation")]
    Failed,
}

impl IrohStoreError {
    /// The `CAPABILITY_UNAVAILABLE` reason: always `transport_key_store_unavailable`
    /// (ADR-0012 §2.4 item 3).
    #[must_use]
    pub fn reason(&self) -> &'static str {
        reason::TRANSPORT_KEY_STORE_UNAVAILABLE
    }

    /// The fixed doctor detail: `locked`, `interaction_not_allowed`, `missing`, `corrupt`,
    /// `unsupported`, `access_denied`, `not_found`, `already_exists` or `failed`.
    #[must_use]
    pub fn detail(&self) -> &'static str {
        match self {
            IrohStoreError::Unavailable(IrohStoreAvailability::Available) => "failed",
            IrohStoreError::Unavailable(a) => a.as_str(),
            IrohStoreError::NotFound => "not_found",
            IrohStoreError::AlreadyExists => "already_exists",
            IrohStoreError::Corrupt => "corrupt",
            IrohStoreError::Failed => "failed",
        }
    }
}

/// The K_iroh custody store of one installation (ADR-0012 §2.4), one item per endpoint ID.
/// Implementations are synchronous, bounded, never prompt, and never fall back to a
/// plaintext file.
pub trait IrohKeyStore: Send + Sync {
    /// The store's kind.
    fn kind(&self) -> IrohStoreKind;

    /// The store's current availability, read without user interaction.
    fn availability(&self) -> IrohStoreAvailability;

    /// The nonsecret locator of `endpoint`'s item, for the `transport_keys` row.
    fn store_ref(&self, endpoint: &IrohEndpointId) -> String;

    /// Store `key` as `endpoint`'s K_iroh. Never overwrites
    /// ([`IrohStoreError::AlreadyExists`]); refuses a key whose endpoint ID is not
    /// `endpoint` ([`IrohStoreError::Corrupt`]).
    ///
    /// # Errors
    /// [`IrohStoreError`].
    fn put(&self, endpoint: &IrohEndpointId, key: &IrohKeyMaterial) -> Result<(), IrohStoreError>;

    /// Read `endpoint`'s K_iroh without user interaction.
    ///
    /// # Errors
    /// [`IrohStoreError::NotFound`] when none is stored; [`IrohStoreError::Corrupt`] when
    /// the bytes do not decode or derive another endpoint ID;
    /// [`IrohStoreError::Unavailable`] when the store is locked or absent.
    fn load(&self, endpoint: &IrohEndpointId) -> Result<IrohKeyMaterial, IrohStoreError>;

    /// Destroy `endpoint`'s item (exactly that item, never by pattern), read back as gone.
    ///
    /// # Errors
    /// [`IrohStoreError::NotFound`] when none is stored.
    fn destroy(&self, endpoint: &IrohEndpointId) -> Result<(), IrohStoreError>;
}

/// Generate a new K_iroh in `store` (ADR-0012 §2.4 item 4, at enable or rotation): the
/// store's availability is checked first and nothing is generated unless it is
/// [`IrohStoreAvailability::Available`]; then the key is put, read back, and the endpoint
/// IDs compared. Returns the new endpoint ID.
///
/// # Errors
/// [`IrohStoreError`]; a CSPRNG failure is [`IrohStoreError::Failed`], a read-back that
/// differs is [`IrohStoreError::Corrupt`].
pub fn create_key(store: &dyn IrohKeyStore) -> Result<IrohEndpointId, IrohStoreError> {
    match store.availability() {
        IrohStoreAvailability::Available => {}
        other => return Err(IrohStoreError::Unavailable(other)),
    }
    let key = IrohKeyMaterial::generate()?;
    let endpoint = key.endpoint_id();
    store.put(&endpoint, &key)?;
    // Read it back: the stored item, not the in-memory copy, is the key from now on.
    let stored = store.load(&endpoint)?;
    if stored.endpoint_id() != endpoint {
        return Err(IrohStoreError::Corrupt);
    }
    Ok(endpoint)
}

/// A doctor finding about the K_iroh store (ADR-0012 §2.4 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IrohDoctorFinding {
    /// Always `transport_key_store_unavailable`.
    pub reason: &'static str,
    /// The store's availability ([`IrohStoreAvailability::as_str`]).
    pub detail: &'static str,
    /// The store examined.
    pub store: IrohStoreKind,
}

/// `None` when `store` is available; otherwise the doctor finding (reason
/// `transport_key_store_unavailable`): the "no verified store" hook of ADR-0012 §2.4
/// item 3.
#[must_use]
pub fn doctor_finding(store: &dyn IrohKeyStore) -> Option<IrohDoctorFinding> {
    match store.availability() {
        IrohStoreAvailability::Available => None,
        other => Some(IrohDoctorFinding {
            reason: reason::TRANSPORT_KEY_STORE_UNAVAILABLE,
            detail: other.as_str(),
            store: store.kind(),
        }),
    }
}

/// The product K_iroh store of this platform for installation `environment`: the macOS
/// login keychain under `account_home` (the account database's home, never `$HOME`),
/// Windows DPAPI in `%LOCALAPPDATA%\Heimdall\iroh\<environment>` (`missing` when
/// `LOCALAPPDATA` is unset), or the Linux Secret Service login collection (`missing` when
/// headless); any other OS gets [`UnsupportedIrohStore`].
#[must_use]
pub fn product_store(environment: &EnvironmentId, account_home: &Path) -> Box<dyn IrohKeyStore> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosLoginKeychainIroh::login(
            account_home,
            environment,
        ))
    }
    #[cfg(windows)]
    {
        let _ = account_home;
        match windows::WindowsDpapiIroh::default_dir(environment) {
            Ok(dir) => Box::new(windows::WindowsDpapiIroh::in_dir(dir, environment)),
            Err(_) => Box::new(MissingProductStore {
                kind: StoreKind::WindowsDpapi,
                environment: environment.clone(),
            }),
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = account_home;
        Box::new(linux::LinuxSecretServiceIroh::new(environment))
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    {
        let _ = (environment, account_home);
        Box::new(UnsupportedIrohStore)
    }
}

/// A product store whose location cannot be resolved (Windows without an absolute
/// `LOCALAPPDATA`): always [`IrohStoreAvailability::Missing`], every operation refused.
#[cfg(windows)]
#[derive(Debug, Clone)]
struct MissingProductStore {
    kind: StoreKind,
    environment: EnvironmentId,
}

#[cfg(windows)]
impl IrohKeyStore for MissingProductStore {
    fn kind(&self) -> IrohStoreKind {
        IrohStoreKind::Product(self.kind)
    }

    fn availability(&self) -> IrohStoreAvailability {
        IrohStoreAvailability::Missing
    }

    fn store_ref(&self, endpoint: &IrohEndpointId) -> String {
        item_label(&self.environment, endpoint)
    }

    fn put(&self, _: &IrohEndpointId, _: &IrohKeyMaterial) -> Result<(), IrohStoreError> {
        Err(IrohStoreError::Unavailable(IrohStoreAvailability::Missing))
    }

    fn load(&self, _: &IrohEndpointId) -> Result<IrohKeyMaterial, IrohStoreError> {
        Err(IrohStoreError::Unavailable(IrohStoreAvailability::Missing))
    }

    fn destroy(&self, _: &IrohEndpointId) -> Result<(), IrohStoreError> {
        Err(IrohStoreError::Unavailable(IrohStoreAvailability::Missing))
    }
}

/// The fixture store's kind name.
pub const FIXTURE_KIND: &str = "fixture_test";

/// **Test store** for K_iroh (fixture custody; mechanism evidence only): an in-memory map
/// from endpoint ID to the store encoding, of kind [`IrohStoreKind::Test`]
/// (`fixture_test`), so it can never satisfy a product-store claim. A lock flag stands in
/// for a locked platform store: while set, every operation is
/// `Unavailable(Locked)`.
pub struct FixtureIrohStore {
    items: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
    locked: AtomicBool,
}

impl std::fmt::Debug for FixtureIrohStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The item count only: never the stored bytes.
        f.debug_struct("FixtureIrohStore")
            .field("items", &self.item_count())
            .field("locked", &self.locked.load(Ordering::SeqCst))
            .finish()
    }
}

impl Default for FixtureIrohStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureIrohStore {
    /// An empty, unlocked store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
            locked: AtomicBool::new(false),
        }
    }

    /// Lock (`true`) or unlock (`false`) the store.
    pub fn set_locked(&self, locked: bool) {
        self.locked.store(locked, Ordering::SeqCst);
    }

    /// How many items are stored (read regardless of the lock, for tests).
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.items
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn check_unlocked(&self) -> Result<(), IrohStoreError> {
        if self.locked.load(Ordering::SeqCst) {
            Err(IrohStoreError::Unavailable(IrohStoreAvailability::Locked))
        } else {
            Ok(())
        }
    }
}

impl IrohKeyStore for FixtureIrohStore {
    fn kind(&self) -> IrohStoreKind {
        IrohStoreKind::Test(FIXTURE_KIND)
    }

    fn availability(&self) -> IrohStoreAvailability {
        if self.locked.load(Ordering::SeqCst) {
            IrohStoreAvailability::Locked
        } else {
            IrohStoreAvailability::Available
        }
    }

    fn store_ref(&self, endpoint: &IrohEndpointId) -> String {
        format!("{ITEM_SERVICE}/{FIXTURE_KIND}/{}", endpoint.as_str())
    }

    fn put(&self, endpoint: &IrohEndpointId, key: &IrohKeyMaterial) -> Result<(), IrohStoreError> {
        self.check_unlocked()?;
        key.check_endpoint(endpoint)?;
        let mut items = self.items.lock().unwrap_or_else(PoisonError::into_inner);
        if items.contains_key(endpoint.as_str()) {
            return Err(IrohStoreError::AlreadyExists);
        }
        items.insert(endpoint.as_str().to_owned(), key.to_store_bytes());
        Ok(())
    }

    fn load(&self, endpoint: &IrohEndpointId) -> Result<IrohKeyMaterial, IrohStoreError> {
        self.check_unlocked()?;
        let items = self.items.lock().unwrap_or_else(PoisonError::into_inner);
        let bytes = items
            .get(endpoint.as_str())
            .ok_or(IrohStoreError::NotFound)?;
        IrohKeyMaterial::from_store_bytes(bytes, endpoint)
    }

    fn destroy(&self, endpoint: &IrohEndpointId) -> Result<(), IrohStoreError> {
        self.check_unlocked()?;
        let mut items = self.items.lock().unwrap_or_else(PoisonError::into_inner);
        items
            .remove(endpoint.as_str())
            .ok_or(IrohStoreError::NotFound)?;
        if items.contains_key(endpoint.as_str()) {
            return Err(IrohStoreError::Failed);
        }
        Ok(())
    }
}

/// A store for a host with no verified persistent store: always
/// [`IrohStoreAvailability::Unsupported`], every operation refused, kind
/// [`IrohStoreKind::Test`] (`unsupported`).
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedIrohStore;

impl IrohKeyStore for UnsupportedIrohStore {
    fn kind(&self) -> IrohStoreKind {
        IrohStoreKind::Test("unsupported")
    }

    fn availability(&self) -> IrohStoreAvailability {
        IrohStoreAvailability::Unsupported
    }

    fn store_ref(&self, endpoint: &IrohEndpointId) -> String {
        format!("{ITEM_SERVICE}/unsupported/{}", endpoint.as_str())
    }

    fn put(&self, _: &IrohEndpointId, _: &IrohKeyMaterial) -> Result<(), IrohStoreError> {
        Err(IrohStoreError::Unavailable(
            IrohStoreAvailability::Unsupported,
        ))
    }

    fn load(&self, _: &IrohEndpointId) -> Result<IrohKeyMaterial, IrohStoreError> {
        Err(IrohStoreError::Unavailable(
            IrohStoreAvailability::Unsupported,
        ))
    }

    fn destroy(&self, _: &IrohEndpointId) -> Result<(), IrohStoreError> {
        Err(IrohStoreError::Unavailable(
            IrohStoreAvailability::Unsupported,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The Ed25519 public key of the all-zero seed (computed independently of this crate;
    /// see the test's comment).
    const ZERO_SEED_PUBLIC: &str =
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    fn is_lower_hex_64(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// The endpoint ID is deterministic for a fixed seed and matches the known-answer
    /// vector for the all-zero seed; different seeds give different IDs.
    #[test]
    fn iroh_endpoint_id_is_deterministic_with_a_known_answer() {
        let zero = IrohKeyMaterial::from_bytes([0u8; 32]);
        assert_eq!(zero.endpoint_id().as_str(), ZERO_SEED_PUBLIC);
        assert_eq!(
            IrohKeyMaterial::from_bytes([0u8; 32]).endpoint_id(),
            zero.endpoint_id()
        );
        let seven = IrohKeyMaterial::from_bytes([7u8; 32]);
        assert_eq!(
            seven.endpoint_id(),
            IrohKeyMaterial::from_bytes([7u8; 32]).endpoint_id()
        );
        assert_ne!(seven.endpoint_id(), zero.endpoint_id());
        assert!(is_lower_hex_64(seven.endpoint_id().as_str()));
        assert_eq!(seven.expose(), &[7u8; 32]);
        // Debug never prints the bytes.
        assert_eq!(format!("{seven:?}"), "IrohKeyMaterial(..)");
        // The store encoding round-trips for its own endpoint only.
        let bytes = seven.to_store_bytes();
        let again = IrohKeyMaterial::from_store_bytes(&bytes, &seven.endpoint_id()).unwrap();
        assert_eq!(again.expose(), seven.expose());
        assert_eq!(
            IrohKeyMaterial::from_store_bytes(&bytes, &zero.endpoint_id()).map(|_| ()),
            Err(IrohStoreError::Corrupt)
        );
        assert_eq!(
            IrohKeyMaterial::from_store_bytes(&[7u8; 32], &seven.endpoint_id()).map(|_| ()),
            Err(IrohStoreError::Corrupt)
        );
        let mut short = bytes.to_vec();
        short.pop();
        assert_eq!(
            IrohKeyMaterial::from_store_bytes(&short, &seven.endpoint_id()).map(|_| ()),
            Err(IrohStoreError::Corrupt)
        );
    }

    /// Mechanism evidence only (fixture custody, test kind): `create_key` generates,
    /// stores and reads back a key under a 64-lowercase-hex endpoint ID; `put` never
    /// overwrites; `destroy` removes exactly that item and another endpoint's item is
    /// unaffected.
    #[test]
    fn iroh_fixture_create_key_round_trip_never_overwrites_and_destroys_exactly() {
        let store = FixtureIrohStore::new();
        assert_eq!(store.kind(), IrohStoreKind::Test("fixture_test"));
        assert_eq!(store.kind().column(), "fixture_test");
        assert_eq!(store.kind().product(), None);
        assert_eq!(doctor_finding(&store), None);

        let first = create_key(&store).unwrap();
        assert!(is_lower_hex_64(first.as_str()));
        let second = create_key(&store).unwrap();
        assert_ne!(first, second);
        assert_eq!(store.item_count(), 2);
        assert_eq!(
            store.store_ref(&first),
            format!("heimdall-iroh/fixture_test/{first}")
        );

        // load returns the same bytes every time, for the right endpoint.
        let loaded = store.load(&first).unwrap();
        assert_eq!(loaded.endpoint_id(), first);
        assert_eq!(store.load(&first).unwrap().expose(), loaded.expose());

        // put never overwrites (not even with the identical key).
        let copy = IrohKeyMaterial::from_bytes(*loaded.expose());
        assert_eq!(store.put(&first, &copy), Err(IrohStoreError::AlreadyExists));
        assert_eq!(store.load(&first).unwrap().expose(), loaded.expose());

        // destroy removes exactly that item.
        store.destroy(&first).unwrap();
        assert_eq!(
            store.load(&first).map(|_| ()),
            Err(IrohStoreError::NotFound)
        );
        assert_eq!(store.destroy(&first), Err(IrohStoreError::NotFound));
        assert_eq!(store.load(&second).unwrap().endpoint_id(), second);
        assert_eq!(store.item_count(), 1);
        assert_eq!(IrohStoreError::NotFound.detail(), "not_found");
        assert_eq!(IrohStoreError::AlreadyExists.detail(), "already_exists");
    }

    /// Mechanism evidence only (fixture custody): a locked store refuses every operation
    /// as `Unavailable(Locked)` with reason `transport_key_store_unavailable`, and
    /// `create_key` generates nothing; unlocked again, the item reads.
    #[test]
    fn iroh_fixture_locked_store_refuses_every_operation() {
        let store = FixtureIrohStore::new();
        let endpoint = create_key(&store).unwrap();
        store.set_locked(true);
        assert_eq!(store.availability(), IrohStoreAvailability::Locked);
        let locked = IrohStoreError::Unavailable(IrohStoreAvailability::Locked);
        let key = IrohKeyMaterial::generate().unwrap();
        let fresh = key.endpoint_id();
        let errors = [
            create_key(&store).map(|_| ()).unwrap_err(),
            store.load(&endpoint).map(|_| ()).unwrap_err(),
            store.put(&fresh, &key).unwrap_err(),
            store.destroy(&endpoint).unwrap_err(),
        ];
        for err in errors {
            assert_eq!(err, locked);
            assert_eq!(err.reason(), reason::TRANSPORT_KEY_STORE_UNAVAILABLE);
            assert_eq!(err.reason(), "transport_key_store_unavailable");
            assert_eq!(err.detail(), "locked");
        }
        assert_eq!(store.item_count(), 1, "nothing generated while locked");
        let finding = doctor_finding(&store).unwrap();
        assert_eq!(finding.reason, reason::TRANSPORT_KEY_STORE_UNAVAILABLE);
        assert_eq!(finding.detail, "locked");
        assert_eq!(finding.store, IrohStoreKind::Test("fixture_test"));

        store.set_locked(false);
        assert_eq!(store.load(&endpoint).unwrap().endpoint_id(), endpoint);
    }

    /// Mechanism evidence only: a key put under another endpoint's ID is refused as
    /// corrupt and nothing is stored.
    #[test]
    fn iroh_fixture_refuses_a_key_under_the_wrong_endpoint() {
        let store = FixtureIrohStore::new();
        let key = IrohKeyMaterial::generate().unwrap();
        let other = IrohKeyMaterial::generate().unwrap().endpoint_id();
        assert_eq!(store.put(&other, &key), Err(IrohStoreError::Corrupt));
        assert_eq!(store.item_count(), 0);
        assert_eq!(
            store.load(&other).map(|_| ()),
            Err(IrohStoreError::NotFound)
        );
        assert_eq!(IrohStoreError::Corrupt.detail(), "corrupt");
        assert_eq!(
            IrohStoreError::Corrupt.reason(),
            reason::TRANSPORT_KEY_STORE_UNAVAILABLE
        );
    }

    /// A host with no verified store: availability `unsupported`, every operation refused,
    /// `create_key` refused, and the doctor finding names `transport_key_store_unavailable`
    /// with detail `unsupported`.
    #[test]
    fn iroh_unsupported_store_gives_the_doctor_finding() {
        let store = UnsupportedIrohStore;
        let finding = doctor_finding(&store).unwrap();
        assert_eq!(finding.reason, "transport_key_store_unavailable");
        assert_eq!(finding.detail, "unsupported");
        assert_eq!(finding.store, IrohStoreKind::Test("unsupported"));
        let err = create_key(&store).unwrap_err();
        assert_eq!(
            err,
            IrohStoreError::Unavailable(IrohStoreAvailability::Unsupported)
        );
        assert_eq!(err.detail(), "unsupported");
        assert_eq!(err.reason(), reason::TRANSPORT_KEY_STORE_UNAVAILABLE);
        let key = IrohKeyMaterial::generate().unwrap();
        let endpoint = key.endpoint_id();
        assert!(store.put(&endpoint, &key).is_err());
        assert!(store.load(&endpoint).is_err());
        assert!(store.destroy(&endpoint).is_err());
    }

    /// The `transport_keys.store_kind` column names.
    #[test]
    fn iroh_store_kind_columns() {
        assert_eq!(
            IrohStoreKind::Product(StoreKind::MacosLoginKeychain).column(),
            "keychain"
        );
        assert_eq!(
            IrohStoreKind::Product(StoreKind::WindowsDpapi).column(),
            "dpapi"
        );
        assert_eq!(
            IrohStoreKind::Product(StoreKind::LinuxSecretService).column(),
            "secret_service"
        );
        assert_eq!(
            IrohStoreKind::Product(StoreKind::WindowsDpapi).product(),
            Some(StoreKind::WindowsDpapi)
        );
        let environment = EnvironmentId::from_random_bytes([6; 16]);
        let endpoint = IrohKeyMaterial::from_bytes([0u8; 32]).endpoint_id();
        assert_eq!(
            item_label(&environment, &endpoint),
            format!("heimdall-iroh/{}/{ZERO_SEED_PUBLIC}", environment.as_str())
        );
    }
}
