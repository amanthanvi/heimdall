//! ⟨M06 U2⟩ K_mgmt, the controller's management key (ADR-0012 §0, §3.4; ADR-0005 §5.1's
//! K_A custody, which K_mgmt follows; m06-plan U2).
//!
//! * **One per controller device and installation.** An Ed25519 key generated from the OS
//!   CSPRNG ([`MgmtKey::generate`]), kept in the verified persistent platform store of that
//!   device ([`MgmtKeyStore`]): the macOS login keychain (a generic-password item; a
//!   file-based keychain item is never iCloud-synchronized), Windows DPAPI for the current
//!   user in the local, non-roaming application data, or the Secret Service login
//!   collection on a Linux desktop. **Desktop controllers only**: where no such store
//!   exists (headless Linux, WSL, a container) the store reports
//!   [`MgmtStoreAvailability::Unsupported`] or [`MgmtStoreAvailability::Missing`] and no
//!   management connection is possible; there is no plaintext fallback (spec §7.3).
//! * **Management only** (R-SE-06): K_mgmt never authenticates onward access and is never
//!   signed by K_ca. It is offered to `ssh` only by the per-session agent
//!   ([`MgmtSigner`]) for a connection rendered by the isolated management configuration
//!   (`heimdall_sshconf::mgmt`).
//! * **Never exported, no backup.** There is no export function and no backup format; a
//!   lost K_mgmt is recovered by re-bootstrapping through independently host-verified
//!   access, or by another owner client inviting a new key (ADR-0012 §3.4). Rotation is
//!   invite-then-revoke (the controller operations, `heimdall_app::remote_env`).
//! * **A locked store** makes management connections unavailable,
//!   `CAPABILITY_UNAVAILABLE` / `mgmt_key_store_locked`
//!   ([`MgmtStoreAvailability::refusal_reason`]); nothing else depends on K_mgmt, so the
//!   runners' work continues.
//! * **Items** are named by [`ITEM_SERVICE`] and the installation's environment ID (the
//!   account), labelled [`item_label`], and deleted by that exact identity only.
//!
//! [`MgmtKey`] cannot be cloned, printed or serialized:
//!
//! ```
//! fn named(_: Option<&heimdall_credential::mgmt::MgmtKey>) {}
//! named(None);
//! ```
//! ```compile_fail,E0277
//! fn needs<T: Clone>() {}
//! needs::<heimdall_credential::mgmt::MgmtKey>();
//! ```
//! ```compile_fail,E0277
//! fn needs<T: std::fmt::Debug>() {}
//! needs::<heimdall_credential::mgmt::MgmtKey>();
//! ```
//! ```compile_fail,E0277
//! fn needs<T: serde::Serialize>() {}
//! needs::<heimdall_credential::mgmt::MgmtKey>();
//! ```
//!
//! **Test stores** ([`fixture::FixtureMgmtStore`]) report a [`MgmtStoreKind::Test`] kind:
//! fixture custody is mechanism evidence only and never satisfies a product-store claim.
//! Tests never touch the owner's keychain, Secret Service or DPAPI items.

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{EnvironmentId, KeyFingerprint};
use heimdall_contract::issuer::StoreKind;
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{HashAlg, PrivateKey, PublicKey, Signature, SigningKey};
use zeroize::Zeroizing;

use crate::vault::SystemRng;

pub mod agent;
pub mod fixture;
mod signer;
pub use agent::SessionAgent;
pub use signer::MgmtSigner;

// The product stores (ADR-0012 §3.4; ADR-0005 §5.2).
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

/// The keychain service, Secret Service application attribute and DPAPI directory name of
/// every K_mgmt item.
pub const ITEM_SERVICE: &str = "heimdall-mgmt";

/// The comment of K_mgmt's public key line (and of its identity in the session agent).
pub const KEY_COMMENT: &str = "heimdall-mgmt";

/// The label of the installation `environment`'s K_mgmt item: `heimdall-mgmt/<environment>`.
#[must_use]
pub fn item_label(environment: &EnvironmentId) -> String {
    format!("{ITEM_SERVICE}/{}", environment.as_str())
}

/// The fixed prefix of a stored K_mgmt secret (then the 32-byte Ed25519 seed), so an item
/// that is not one of ours reads as corrupt rather than as a key.
const SECRET_MAGIC: &[u8] = b"heimdall-mgmt/1 ed25519\0";

/// The Ed25519 seed length.
const SEED_BYTES: usize = 32;

/// Why a K_mgmt key operation failed. Messages carry no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum MgmtKeyError {
    /// The OS CSPRNG failed: no key was made.
    #[error("the system random number generator is unavailable")]
    RandomnessUnavailable,
    /// The stored bytes are not a K_mgmt secret.
    #[error("the stored management key is corrupt")]
    Corrupt,
    /// The key or a signature could not be encoded or produced.
    #[error("the management key could not be used")]
    Encoding,
}

/// K_mgmt's private key. No `Clone`, `Debug`, `Display`, `Serialize` or `Deserialize`, and
/// no export: the only ways out of it are its public half, a signature, and the store
/// encoding a [`MgmtKeyStore`] writes into its platform store.
pub struct MgmtKey {
    seed: Zeroizing<[u8; SEED_BYTES]>,
}

impl MgmtKey {
    /// A new key from the OS CSPRNG.
    ///
    /// # Errors
    /// [`MgmtKeyError::RandomnessUnavailable`].
    pub fn generate() -> Result<MgmtKey, MgmtKeyError> {
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        SystemRng::fill(seed.as_mut_slice()).map_err(|_| MgmtKeyError::RandomnessUnavailable)?;
        Ok(MgmtKey { seed })
    }

    /// The store encoding (magic, then the seed), for a [`MgmtKeyStore`] implementation to
    /// write into its platform store and nowhere else.
    #[must_use]
    pub fn to_store_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(SECRET_MAGIC.len() + SEED_BYTES));
        out.extend_from_slice(SECRET_MAGIC);
        out.extend_from_slice(self.seed.as_slice());
        out
    }

    /// Decode [`Self::to_store_bytes`]'s encoding.
    ///
    /// # Errors
    /// [`MgmtKeyError::Corrupt`].
    pub fn from_store_bytes(bytes: &[u8]) -> Result<MgmtKey, MgmtKeyError> {
        let seed = bytes
            .strip_prefix(SECRET_MAGIC)
            .filter(|s| s.len() == SEED_BYTES)
            .ok_or(MgmtKeyError::Corrupt)?;
        let mut out = Zeroizing::new([0u8; SEED_BYTES]);
        out.copy_from_slice(seed);
        Ok(MgmtKey { seed: out })
    }

    fn keypair(&self) -> Ed25519Keypair {
        Ed25519Keypair::from_seed(&self.seed)
    }

    /// The public half.
    ///
    /// # Errors
    /// [`MgmtKeyError::Encoding`] (never for a key this module made).
    pub fn public(&self) -> Result<MgmtPublicKey, MgmtKeyError> {
        let key = PublicKey::new(self.keypair().public.into(), KEY_COMMENT);
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        Ok(MgmtPublicKey {
            openssh_line: key.to_openssh().map_err(|_| MgmtKeyError::Encoding)?,
            blob: key.to_bytes().map_err(|_| MgmtKeyError::Encoding)?,
            fingerprint: KeyFingerprint::parse(&fingerprint).map_err(|_| MgmtKeyError::Encoding)?,
        })
    }

    /// Sign `data`: the SSH signature blob (`string "ssh-ed25519"`, `string signature`), the
    /// form an agent's sign response carries.
    ///
    /// # Errors
    /// [`MgmtKeyError::Encoding`].
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, MgmtKeyError> {
        let key = PrivateKey::new(KeypairData::Ed25519(self.keypair()), "")
            .map_err(|_| MgmtKeyError::Encoding)?;
        let signature = try_sign(&key, data).ok_or(MgmtKeyError::Encoding)?;
        Vec::<u8>::try_from(signature).map_err(|_| MgmtKeyError::Encoding)
    }
}

/// Sign through `ssh-key`'s `SigningKey` (its `Signer<Signature>` supertrait).
fn try_sign<K: SigningKey>(key: &K, data: &[u8]) -> Option<Signature> {
    key.try_sign(data).ok()
}

/// The OpenSSH SHA-256 fingerprint (`SHA256:…`) of one public key line (`<type> <base64>
/// [comment]`); `None` for anything else. Public data: what the owner compares on both
/// devices (ADR-0012 §3.9 item 1).
#[must_use]
pub fn openssh_fingerprint(line: &str) -> Option<KeyFingerprint> {
    if line.chars().any(char::is_control) {
        return None;
    }
    let key = PublicKey::from_openssh(line.trim()).ok()?;
    KeyFingerprint::parse(&key.fingerprint(HashAlg::Sha256).to_string()).ok()
}

/// K_mgmt's public half (safe to show, persist and send: the invitation's `public_key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MgmtPublicKey {
    /// `ssh-ed25519 AAAA… heimdall-mgmt`.
    pub openssh_line: String,
    /// The SSH wire encoding (what the session agent lists).
    pub blob: Vec<u8>,
    /// `SHA256:…`, which the owner compares on both devices (ADR-0012 §3.9 item 1).
    pub fingerprint: KeyFingerprint,
}

/// The kind of a [`MgmtKeyStore`]: a product store (the public `StoreKind` names), or a
/// test store named by the test (never a product claim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MgmtStoreKind {
    /// A product platform store.
    Product(StoreKind),
    /// A test store (fixture custody: mechanism evidence only).
    Test(&'static str),
}

impl MgmtStoreKind {
    /// The product kind, when this is one.
    #[must_use]
    pub fn product(self) -> Option<StoreKind> {
        match self {
            MgmtStoreKind::Product(kind) => Some(kind),
            MgmtStoreKind::Test(_) => None,
        }
    }
}

/// A K_mgmt store's availability (as K_ca's, ADR-0008 D1). Anything but
/// [`MgmtStoreAvailability::Available`] makes management connections unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MgmtStoreAvailability {
    /// The store can be read without interaction.
    Available,
    /// The store is locked.
    Locked,
    /// A read would need user interaction, which is never allowed.
    InteractionNotAllowed,
    /// The store (or its service) is absent.
    Missing,
    /// The store answered with data that does not decode.
    Corrupt,
    /// No verified persistent store exists here (headless Linux, WSL, a container, a
    /// runner): K_mgmt is for desktop controllers only.
    Unsupported,
    /// The store is unlocked but the item's access list does not trust this executable.
    AccessDenied,
}

impl MgmtStoreAvailability {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MgmtStoreAvailability::Available => "available",
            MgmtStoreAvailability::Locked => "locked",
            MgmtStoreAvailability::InteractionNotAllowed => "interaction_not_allowed",
            MgmtStoreAvailability::Missing => "missing",
            MgmtStoreAvailability::Corrupt => "corrupt",
            MgmtStoreAvailability::Unsupported => "unsupported",
            MgmtStoreAvailability::AccessDenied => "access_denied",
        }
    }

    /// The `CAPABILITY_UNAVAILABLE` reason, `None` when available: `mgmt_key_store_locked`
    /// when an owner unlock can help (ADR-0012 §3.4); otherwise ⟨rev6.2⟩
    /// `mgmt_key_store_unavailable` (absent, unsupported, corrupt, or an access list that does
    /// not trust this executable: unlocking cannot help).
    #[must_use]
    pub fn refusal_reason(self) -> Option<&'static str> {
        match self {
            MgmtStoreAvailability::Available => None,
            MgmtStoreAvailability::Locked | MgmtStoreAvailability::InteractionNotAllowed => {
                Some(reason::MGMT_KEY_STORE_LOCKED)
            }
            MgmtStoreAvailability::Missing
            | MgmtStoreAvailability::Corrupt
            | MgmtStoreAvailability::Unsupported
            | MgmtStoreAvailability::AccessDenied => Some(reason::MGMT_KEY_STORE_UNAVAILABLE),
        }
    }
}

/// A store operation's failure. Messages carry no item content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum MgmtStoreError {
    /// The store is not available.
    #[error("the management key store is unavailable ({})", .0.as_str())]
    Unavailable(MgmtStoreAvailability),
    /// No K_mgmt item exists for this installation.
    #[error("no management key is stored for this installation")]
    NotFound,
    /// A K_mgmt item already exists (`put` never overwrites).
    #[error("a management key is already stored for this installation")]
    AlreadyExists,
    /// The item exists but does not decode.
    #[error("the stored management key is corrupt")]
    Corrupt,
    /// The store refused the operation for another reason.
    #[error("the management key store refused the operation")]
    Failed,
}

impl MgmtStoreError {
    /// The `CAPABILITY_UNAVAILABLE` reason of an unavailable store
    /// ([`MgmtStoreAvailability::refusal_reason`]); `None` for the other failures.
    #[must_use]
    pub fn refusal_reason(&self) -> Option<&'static str> {
        match self {
            MgmtStoreError::Unavailable(a) => a.refusal_reason(),
            _ => None,
        }
    }
}

/// The K_mgmt custody store of one installation (ADR-0012 §3.4). Implementations are
/// synchronous, bounded, never prompt, and never fall back to a plaintext file.
pub trait MgmtKeyStore: Send + Sync {
    /// The store's kind.
    fn kind(&self) -> MgmtStoreKind;

    /// The store's current availability, read without user interaction.
    fn availability(&self) -> MgmtStoreAvailability;

    /// Store `key` as this installation's K_mgmt. Never overwrites an existing item
    /// ([`MgmtStoreError::AlreadyExists`]).
    ///
    /// # Errors
    /// [`MgmtStoreError`].
    fn put(&self, key: &MgmtKey) -> Result<(), MgmtStoreError>;

    /// Read this installation's K_mgmt without user interaction.
    ///
    /// # Errors
    /// [`MgmtStoreError::NotFound`] when none is stored; [`MgmtStoreError::Unavailable`]
    /// when the store is locked or absent.
    fn load(&self) -> Result<MgmtKey, MgmtStoreError>;

    /// Destroy this installation's K_mgmt item (exactly that item; never by pattern).
    ///
    /// # Errors
    /// [`MgmtStoreError::NotFound`] when none is stored.
    fn destroy(&self) -> Result<(), MgmtStoreError>;
}

/// The installation's K_mgmt, generated and stored first when none exists (`true` when it
/// was created now). A locked or absent store refuses before anything is generated.
///
/// # Errors
/// [`MgmtStoreError`]; a CSPRNG failure is [`MgmtStoreError::Failed`].
pub fn load_or_create(store: &dyn MgmtKeyStore) -> Result<(MgmtKey, bool), MgmtStoreError> {
    match store.availability() {
        MgmtStoreAvailability::Available => {}
        other => return Err(MgmtStoreError::Unavailable(other)),
    }
    match store.load() {
        Ok(key) => return Ok((key, false)),
        Err(MgmtStoreError::NotFound) => {}
        Err(e) => return Err(e),
    }
    let key = MgmtKey::generate().map_err(|_| MgmtStoreError::Failed)?;
    store.put(&key)?;
    // Read it back: the stored item, not the in-memory copy, is the key from now on.
    let stored = store.load()?;
    let same = stored.public().map_err(|_| MgmtStoreError::Corrupt)?
        == key.public().map_err(|_| MgmtStoreError::Corrupt)?;
    if !same {
        return Err(MgmtStoreError::Corrupt);
    }
    Ok((stored, true))
}

/// A store for a host with no verified persistent store: always
/// [`MgmtStoreAvailability::Unsupported`], every operation refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedStore;

impl MgmtKeyStore for UnsupportedStore {
    fn kind(&self) -> MgmtStoreKind {
        MgmtStoreKind::Test("unsupported")
    }

    fn availability(&self) -> MgmtStoreAvailability {
        MgmtStoreAvailability::Unsupported
    }

    fn put(&self, _key: &MgmtKey) -> Result<(), MgmtStoreError> {
        Err(MgmtStoreError::Unavailable(
            MgmtStoreAvailability::Unsupported,
        ))
    }

    fn load(&self) -> Result<MgmtKey, MgmtStoreError> {
        Err(MgmtStoreError::Unavailable(
            MgmtStoreAvailability::Unsupported,
        ))
    }

    fn destroy(&self) -> Result<(), MgmtStoreError> {
        Err(MgmtStoreError::Unavailable(
            MgmtStoreAvailability::Unsupported,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::fixture::FixtureMgmtStore;
    use super::*;

    #[test]
    fn keys_round_trip_through_the_store_encoding_and_sign() {
        let key = MgmtKey::generate().unwrap();
        let public = key.public().unwrap();
        assert!(public.openssh_line.starts_with("ssh-ed25519 AAAA"));
        assert!(public.openssh_line.ends_with(" heimdall-mgmt"));
        assert!(public.fingerprint.as_str().starts_with("SHA256:"));
        let again = MgmtKey::from_store_bytes(&key.to_store_bytes()).unwrap();
        assert_eq!(again.public().unwrap(), public);
        // A signature verifies under the public key (through an SSHSIG over the same bytes,
        // as `credential_memory` verifies the vault's keys).
        let pk = PublicKey::from_bytes(&public.blob).unwrap();
        let data = ssh_key::SshSig::signed_data("hm-test", HashAlg::Sha512, b"challenge").unwrap();
        let sig = Signature::try_from(key.sign(&data).unwrap().as_slice()).unwrap();
        let sshsig =
            ssh_key::SshSig::new(pk.key_data().clone(), "hm-test", HashAlg::Sha512, sig).unwrap();
        assert!(pk.verify("hm-test", b"challenge", &sshsig).is_ok());
        assert!(pk.verify("hm-test", b"other", &sshsig).is_err());
        // Foreign or truncated bytes are corrupt, never a key.
        assert!(MgmtKey::from_store_bytes(&[0u8; 32]).is_err());
        let mut short = key.to_store_bytes().to_vec();
        short.pop();
        assert!(MgmtKey::from_store_bytes(&short).is_err());
        // Two keys differ.
        assert_ne!(MgmtKey::generate().unwrap().public().unwrap(), public);
        // The fingerprint of the line is the key's.
        assert_eq!(
            openssh_fingerprint(&public.openssh_line),
            Some(public.fingerprint.clone())
        );
        assert_eq!(openssh_fingerprint("ssh-ed25519 notbase64"), None);
        assert_eq!(openssh_fingerprint("not a key"), None);
    }

    /// m06-plan U2 "K_mgmt in a locked store gives `mgmt_key_store_locked`" (fixture store,
    /// test kind): a locked store refuses `load_or_create` before anything is generated, with
    /// the locked reason; unlocked, the key is created once and then read back unchanged.
    #[test]
    fn locked_store_refuses_with_mgmt_key_store_locked() {
        let store = FixtureMgmtStore::in_memory();
        assert_eq!(store.kind(), MgmtStoreKind::Test("fixture_test"));
        assert_eq!(store.kind().product(), None);
        store.lock();
        let err = load_or_create(&store).map(|_| ()).unwrap_err();
        assert_eq!(
            err,
            MgmtStoreError::Unavailable(MgmtStoreAvailability::Locked)
        );
        assert_eq!(err.refusal_reason(), Some(reason::MGMT_KEY_STORE_LOCKED));
        assert!(!store.holds_item(), "nothing generated while locked");
        store.unlock();
        let (key, created) = load_or_create(&store).unwrap();
        assert!(created);
        let (again, created) = load_or_create(&store).unwrap();
        assert!(!created);
        assert_eq!(again.public().unwrap(), key.public().unwrap());
        // Locked again: the stored key stays, management is unavailable.
        store.lock();
        assert_eq!(
            store.load().map(|_| ()).unwrap_err(),
            MgmtStoreError::Unavailable(MgmtStoreAvailability::Locked)
        );
        assert!(store.holds_item());
        assert_eq!(
            MgmtStoreAvailability::InteractionNotAllowed.refusal_reason(),
            Some(reason::MGMT_KEY_STORE_LOCKED)
        );
        assert_eq!(
            UnsupportedStore.availability().refusal_reason(),
            Some(reason::MGMT_KEY_STORE_UNAVAILABLE)
        );
        assert!(UnsupportedStore.load().is_err());
    }

    #[test]
    fn put_never_overwrites_and_destroy_removes_exactly_the_item() {
        let store = FixtureMgmtStore::in_memory();
        let first = MgmtKey::generate().unwrap();
        store.put(&first).unwrap();
        assert_eq!(
            store.put(&MgmtKey::generate().unwrap()),
            Err(MgmtStoreError::AlreadyExists)
        );
        assert_eq!(
            store.load().unwrap().public().unwrap(),
            first.public().unwrap()
        );
        store.destroy().unwrap();
        assert_eq!(store.destroy(), Err(MgmtStoreError::NotFound));
        assert_eq!(
            store.load().map(|_| ()).unwrap_err(),
            MgmtStoreError::NotFound
        );
    }
}
