//! The key vault (ADR-0008 D1, D2; m03-plan U1 `vault::KeyVault`): K_env and K_verify
//! in a [`SecretKey`] (no `Clone`, `Debug`, `Display`, `Serialize`, `Deserialize`;
//! zeroized on drop; its page locked where the platform allows), handed out only as
//! opaque random 128-bit [`VaultSlot`] handles.
//!
//! * [`KeyVault::generate_ed25519`] draws the Ed25519 seed from [`SystemRng`] (the OS
//!   CSPRNG through `getrandom`; ADR-0008 §17.15 item 11) **directly into the key's
//!   locked page**, and returns the slot and the public half ([`PublicKeyInfo`]). The
//!   slot is random too; its hex ([`VaultSlot::to_hex`]) is the `key_handle_ref`
//!   persisted in the credential instance. Nothing secret is ever persisted.
//! * [`KeyVault::sign`] returns the SSH signature blob (`string "ssh-ed25519"`,
//!   `string signature[64]`), the form `SSH_AGENT_SIGN_RESPONSE` carries. The purpose
//!   and authorization checks (ADR-0008 D2 items 3–4) are the signer's (U2), before
//!   this call.
//! * [`KeyVault::destroy`] zeroizes and drops a key; [`KeyVault::contains`] is what
//!   restart recovery and the signer ask (U0b row 8: an `installed` instance whose slot
//!   is not in this process is `lost`).
//! * **Memory.** Each key lives on a page of its own (an aligned page inside a two-page
//!   allocation the key owns), locked with [`crate::sys::lock_pages`] before the seed
//!   is written. A lock the OS refuses is a degraded mitigation
//!   ([`KeyVault::pages_locked`] is `Some(false)`) and never refuses the key (D1).
//!   Signing derives the keypair from the seed on the stack for the one call;
//!   `ssh-key`'s and `ed25519-dalek`'s key types zeroize those copies on drop.
//! * **Test seed** (m03-plan U0b row 16; ADR-0008 D13 item 5). Only in builds with
//!   `debug_assertions`, the project's test configuration (`heimdall::testcfg`, whose
//!   `HEIMDALL_TEST_KEY_SEED` a release build refuses with exit 2):
//!   `KeyVault::with_test_seed(seed)` derives the n-th key's (0-based) Ed25519 seed as
//!   `SHA-256(b"heimdall-test-key-seed/k_env/v1\0" ‖ u64be(n) ‖ seed)`, the one rule
//!   `heimdall_testkit::managed::seeded_k_env_nth` also states, so a canary scan can
//!   recompute the exact private bytes (`seeded_private_key`). A release build has
//!   neither function.
//!
//! `SecretKey` cannot be cloned, printed or serialized; each of these is a
//! compile-fail test (the first block compiles and shows the type is nameable, so each
//! failure below is the missing trait, `E0277`):
//!
//! ```
//! fn named(_: Option<&heimdall_credential::vault::SecretKey>) {}
//! named(None);
//! ```
//! ```compile_fail,E0277
//! fn needs<T: Clone>() {}
//! needs::<heimdall_credential::vault::SecretKey>();
//! ```
//! ```compile_fail,E0277
//! fn needs<T: std::fmt::Debug>() {}
//! needs::<heimdall_credential::vault::SecretKey>();
//! ```
//! ```compile_fail,E0277
//! fn needs<T: std::fmt::Display>() {}
//! needs::<heimdall_credential::vault::SecretKey>();
//! ```
//! ```compile_fail,E0277
//! fn needs<T: serde::Serialize>() {}
//! needs::<heimdall_credential::vault::SecretKey>();
//! ```
//! ```compile_fail,E0277
//! fn needs<T: serde::de::DeserializeOwned>() {}
//! needs::<heimdall_credential::vault::SecretKey>();
//! ```
//! ```
//! // The control for the two serde blocks: the bound itself compiles.
//! fn needs<T: serde::Serialize + serde::de::DeserializeOwned>() {}
//! needs::<String>();
//! ```

use std::collections::HashMap;
use std::sync::RwLock;

use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::public::Ed25519PublicKey;
use ssh_key::rand_core::{CryptoRng, Error as RngError, RngCore};
use ssh_key::{HashAlg, PrivateKey, PublicKey, Signature, SigningKey};
use zeroize::{Zeroize, Zeroizing};

use crate::sys::{self, MemLock};

/// The operating system's CSPRNG through `getrandom` (ADR-0008 §17.15 item 11,
/// D-Q3): the only randomness source for K_env, K_verify, K_ca, serials, vault
/// handles, backup salts and passphrases.
///
/// It implements `ssh-key`'s re-exported `rand_core` 0.6 traits for the `ssh-key`
/// APIs that take an RNG (`PrivateKey::encrypt`). [`RngCore::try_fill_bytes`] reports
/// a CSPRNG failure; the infallible [`RngCore::fill_bytes`] (which `rand_core`'s
/// trait requires) **aborts the process** on one rather than return predictable
/// bytes: a key generated from a failed CSPRNG is never produced.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRng;

/// The CSPRNG failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("the system random number generator is unavailable")]
pub struct RandomnessUnavailable;

impl SystemRng {
    /// Fill `buf` from the operating system's CSPRNG.
    ///
    /// # Errors
    /// [`RandomnessUnavailable`].
    pub fn fill(buf: &mut [u8]) -> Result<(), RandomnessUnavailable> {
        getrandom::fill(buf).map_err(|_| RandomnessUnavailable)
    }
}

impl RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if Self::fill(dest).is_err() {
            // Fail closed: never continue with bytes that did not come from the CSPRNG.
            std::process::abort();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        Self::fill(dest).map_err(|_| {
            RngError::from(
                core::num::NonZeroU32::new(RngError::CUSTOM_START)
                    .unwrap_or(core::num::NonZeroU32::MIN),
            )
        })
    }
}

impl CryptoRng for SystemRng {}

// --- slots and public halves ----------------------------------------------------------

/// The length of a [`VaultSlot`] in bytes (128 bits).
pub const SLOT_BYTES: usize = 16;

/// An opaque, random 128-bit handle to one key in a [`KeyVault`] (m03-plan U1). It
/// carries no key material and is not derived from any ID; its hex
/// ([`VaultSlot::to_hex`]) is the credential instance's `key_handle_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VaultSlot([u8; SLOT_BYTES]);

impl VaultSlot {
    /// 32 lowercase hex characters (the persisted `key_handle_ref`).
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse [`VaultSlot::to_hex`]'s form (exactly 32 lowercase hex characters).
    #[must_use]
    pub fn from_hex(text: &str) -> Option<VaultSlot> {
        let bytes = text.as_bytes();
        if bytes.len() != SLOT_BYTES * 2 {
            return None;
        }
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        let mut out = [0u8; SLOT_BYTES];
        for (i, [hi, lo]) in bytes.as_chunks::<2>().0.iter().enumerate() {
            out[i] = (digit(*hi)? << 4) | digit(*lo)?;
        }
        Some(VaultSlot(out))
    }
}

impl std::fmt::Display for VaultSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The public half of a vault key (safe to show, list and persist).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// `ssh-ed25519 AAAA…`, no comment (the per-binding `key.pub` line).
    pub openssh_line: String,
    /// The SSH wire encoding of the public key (what an agent lists).
    pub blob: Vec<u8>,
    /// `SHA256:…` (the subject fingerprint a reservation records).
    pub fingerprint: String,
}

impl PublicKeyInfo {
    fn of(public: Ed25519PublicKey) -> Result<PublicKeyInfo, VaultError> {
        let key = PublicKey::from(public);
        Ok(PublicKeyInfo {
            openssh_line: key.to_openssh().map_err(|_| VaultError::Encoding)?,
            blob: key.to_bytes().map_err(|_| VaultError::Encoding)?,
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        })
    }

    /// The public key as an `ssh-key` value (for building a certificate).
    ///
    /// # Errors
    /// [`VaultError::Encoding`] (never for a blob this vault produced).
    pub fn public_key(&self) -> Result<PublicKey, VaultError> {
        PublicKey::from_bytes(&self.blob).map_err(|_| VaultError::Encoding)
    }
}

/// Why a vault operation failed. Messages carry no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// The operating system's CSPRNG failed: no key was made.
    #[error("the system random number generator is unavailable")]
    RandomnessUnavailable,
    /// No key in this vault has this slot (never generated, or destroyed).
    #[error("no key in this vault has this slot")]
    NoSuchSlot,
    /// The vault's lock was poisoned by a panic; it refuses to sign or generate (keys
    /// can still be destroyed).
    #[error("the key vault is unavailable")]
    Unavailable,
    /// A test seed outside 1 to 64 bytes.
    #[error("the test key seed must be 1 to 64 bytes")]
    InvalidSeed,
    /// The signature could not be produced.
    #[error("the signature could not be produced")]
    Signing,
    /// A public key or signature could not be encoded.
    #[error("the key could not be encoded")]
    Encoding,
}

// --- the secret key -------------------------------------------------------------------

/// The Ed25519 seed length.
const SEED_BYTES: usize = 32;

/// One K_env or K_verify private key (ADR-0008 D1). Its only operation is signing; it
/// has no `Clone`, `Debug`, `Display`, `Serialize` or `Deserialize` (see the module's
/// compile-fail tests), no public constructor and no accessor, and no
/// [`KeyVault`] method hands one out: the type is public only so those tests can name
/// it. Its seed sits on a page the key owns alone, locked against swap where the
/// platform allows, and is zeroized on drop, before the page is unlocked and freed.
pub struct SecretKey {
    /// The page lock; released in `drop` after the bytes are zeroized.
    lock: Option<MemLock>,
    /// Two pages (or more); the key's own page starts at `offset`.
    buf: Box<[u8]>,
    /// Start of the seed (the key's exclusive page, or 0 when no page fits).
    offset: usize,
}

impl SecretKey {
    /// A key whose seed `fill` writes, after the page is locked.
    fn new(
        fill: impl FnOnce(&mut [u8; SEED_BYTES]) -> Result<(), VaultError>,
    ) -> Result<SecretKey, VaultError> {
        let page = sys::page_size().max(SEED_BYTES);
        let mut buf = vec![0u8; page.saturating_mul(2)].into_boxed_slice();
        let base = buf.as_ptr().addr();
        let (offset, lock) = match sys::exclusive_page(&mut buf, page) {
            Some(region) => {
                let offset = region.as_ptr().addr() - base;
                (offset, sys::lock_pages(region))
            }
            None => (0, MemLock::none()),
        };
        let mut key = SecretKey {
            lock: Some(lock),
            buf,
            offset,
        };
        fill(key.seed_mut())?;
        Ok(key)
    }

    fn seed_mut(&mut self) -> &mut [u8; SEED_BYTES] {
        let range = self.offset..self.offset + SEED_BYTES;
        // The range lies inside `buf` by construction (an exclusive page of at least
        // SEED_BYTES, or the start of a buffer of at least 2 × SEED_BYTES).
        match self
            .buf
            .get_mut(range)
            .and_then(|s| <&mut [u8; SEED_BYTES]>::try_from(s).ok())
        {
            Some(seed) => seed,
            None => unreachable_seed(),
        }
    }

    fn keypair(&self) -> Option<Ed25519Keypair> {
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        seed.copy_from_slice(self.buf.get(self.offset..self.offset + SEED_BYTES)?);
        Some(Ed25519Keypair::from_seed(&seed))
    }

    fn public(&self) -> Option<Ed25519PublicKey> {
        self.keypair().map(|pair| pair.public)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let pair = self.keypair().ok_or(VaultError::Signing)?;
        // `PrivateKey` zeroizes its key data on drop, like the keypair it wraps.
        let key =
            PrivateKey::new(KeypairData::Ed25519(pair), "").map_err(|_| VaultError::Signing)?;
        let signature = try_sign(&key, data).ok_or(VaultError::Signing)?;
        Vec::<u8>::try_from(signature).map_err(|_| VaultError::Encoding)
    }

    fn pages_locked(&self) -> bool {
        self.lock.as_ref().is_some_and(MemLock::is_locked)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zeroize first, then unlock (the bytes are still mapped), then free.
        self.buf.zeroize();
        drop(self.lock.take());
    }
}

/// The seed range is inside the buffer by construction; reaching this is a defect.
/// It aborts rather than continue with a key that is not where the lock is.
#[cold]
fn unreachable_seed() -> ! {
    std::process::abort()
}

/// Sign through `ssh-key`'s `SigningKey` (its `Signer<Signature>` supertrait).
fn try_sign<K: SigningKey>(key: &K, data: &[u8]) -> Option<Signature> {
    key.try_sign(data).ok()
}

// --- the vault ------------------------------------------------------------------------

/// The in-memory key vault of one runtime (ADR-0008 D1, D2). Keys exist only here and
/// only for this process's lifetime; dropping the vault zeroizes every key.
pub struct KeyVault {
    keys: RwLock<HashMap<VaultSlot, SecretKey>>,
    #[cfg(debug_assertions)]
    test_seed: Option<test_seed::TestSeed>,
}

impl std::fmt::Debug for KeyVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.keys.read().map(|k| k.len()).ok();
        f.debug_struct("KeyVault")
            .field("keys", &n)
            .finish_non_exhaustive()
    }
}

impl Default for KeyVault {
    fn default() -> Self {
        KeyVault::new()
    }
}

impl KeyVault {
    /// An empty vault whose keys come from the OS CSPRNG.
    #[must_use]
    pub fn new() -> KeyVault {
        KeyVault {
            keys: RwLock::new(HashMap::new()),
            #[cfg(debug_assertions)]
            test_seed: None,
        }
    }

    /// Generate an Ed25519 key (K_env or K_verify) and return its slot and public
    /// half.
    ///
    /// # Errors
    /// [`VaultError::RandomnessUnavailable`] (nothing is kept);
    /// [`VaultError::Unavailable`] (poisoned lock); [`VaultError::Encoding`].
    pub fn generate_ed25519(&self) -> Result<(VaultSlot, PublicKeyInfo), VaultError> {
        let key = self.new_key()?;
        let public = key.public().ok_or(VaultError::Encoding)?;
        let info = PublicKeyInfo::of(public)?;
        let mut keys = self.keys.write().map_err(|_| VaultError::Unavailable)?;
        let slot = loop {
            let mut bytes = [0u8; SLOT_BYTES];
            SystemRng::fill(&mut bytes).map_err(|_| VaultError::RandomnessUnavailable)?;
            let slot = VaultSlot(bytes);
            if !keys.contains_key(&slot) {
                break slot;
            }
        };
        keys.insert(slot, key);
        Ok((slot, info))
    }

    fn new_key(&self) -> Result<SecretKey, VaultError> {
        #[cfg(debug_assertions)]
        if let Some(seed) = &self.test_seed {
            let index = seed.next_index();
            return SecretKey::new(|out| {
                seed.derive_into(index, out);
                Ok(())
            });
        }
        SecretKey::new(|out| SystemRng::fill(out).map_err(|_| VaultError::RandomnessUnavailable))
    }

    /// Sign `data` with the key in `slot`: the SSH signature blob (`string
    /// "ssh-ed25519"`, `string signature[64]`). Callers have already run the purpose
    /// and authorization checks (ADR-0008 D2 items 3–4).
    ///
    /// # Errors
    /// [`VaultError::NoSuchSlot`]; [`VaultError::Unavailable`] (poisoned lock);
    /// [`VaultError::Signing`]; [`VaultError::Encoding`].
    pub fn sign(&self, slot: &VaultSlot, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let keys = self.keys.read().map_err(|_| VaultError::Unavailable)?;
        keys.get(slot).ok_or(VaultError::NoSuchSlot)?.sign(data)
    }

    /// Zeroize and drop the key in `slot` (ADR-0008 D2 item 7). Idempotent; works even
    /// when the lock was poisoned (destruction never fails closed into keeping a key).
    pub fn destroy(&self, slot: &VaultSlot) {
        let removed = match self.keys.write() {
            Ok(mut keys) => keys.remove(slot),
            Err(poisoned) => poisoned.into_inner().remove(slot),
        };
        drop(removed);
    }

    /// Zeroize and drop every key (process exit, `TIME_UNCERTAIN` closure; D1).
    pub fn destroy_all(&self) {
        let removed = match self.keys.write() {
            Ok(mut keys) => std::mem::take(&mut *keys),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        drop(removed);
    }

    /// Whether `slot` holds a key in this process. A poisoned lock answers `false`.
    #[must_use]
    pub fn contains(&self, slot: &VaultSlot) -> bool {
        self.keys.read().is_ok_and(|keys| keys.contains_key(slot))
    }

    /// The public half of the key in `slot`, if present.
    #[must_use]
    pub fn public_key(&self, slot: &VaultSlot) -> Option<PublicKeyInfo> {
        let keys = self.keys.read().ok()?;
        let public = keys.get(slot)?.public()?;
        PublicKeyInfo::of(public).ok()
    }

    /// Whether the key in `slot` has its page locked against swap (`Some(false)` is
    /// the degraded mitigation of ADR-0008 D1; `None` when the slot is absent).
    #[must_use]
    pub fn pages_locked(&self, slot: &VaultSlot) -> Option<bool> {
        let keys = self.keys.read().ok()?;
        keys.get(slot).map(SecretKey::pages_locked)
    }

    /// The number of keys held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.read().map_or(0, |keys| keys.len())
    }

    /// Whether the vault holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(debug_assertions)]
impl KeyVault {
    /// **Test configuration only** (`debug_assertions`; m03-plan U0b row 16, ADR-0008
    /// D13 item 5): a vault whose n-th generated key (n = 0, 1, …) is derived from
    /// `seed` ([`seeded_private_key`]), so a canary scan can look for the exact private
    /// bytes. Slots stay random. A release build has no such constructor.
    ///
    /// # Errors
    /// [`VaultError::InvalidSeed`] unless `seed` is 1 to 64 bytes
    /// (`HEIMDALL_TEST_KEY_SEED`'s bounds).
    pub fn with_test_seed(seed: &[u8]) -> Result<KeyVault, VaultError> {
        Ok(KeyVault {
            keys: RwLock::new(HashMap::new()),
            test_seed: Some(test_seed::TestSeed::new(seed)?),
        })
    }
}

/// **Test configuration only** (`debug_assertions`): the 32-byte Ed25519 private seed
/// of the `index`-th key a `KeyVault::with_test_seed(seed)` generates, for canary
/// scans (ADR-0008 D13 item 5). `None` for a seed outside 1 to 64 bytes.
#[cfg(debug_assertions)]
#[must_use]
pub fn seeded_private_key(seed: &[u8], index: u64) -> Option<Zeroizing<[u8; 32]>> {
    let seed = test_seed::TestSeed::new(seed).ok()?;
    let mut out = Zeroizing::new([0u8; 32]);
    seed.derive_into(index, &mut out);
    Some(out)
}

#[cfg(debug_assertions)]
mod test_seed {
    use std::sync::atomic::{AtomicU64, Ordering};

    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    use super::VaultError;

    /// The domain-separation label of the derivation (version 1; the same bytes as
    /// `heimdall_testkit::managed::K_ENV_SEED_LABEL`).
    pub(super) const LABEL: &[u8] = b"heimdall-test-key-seed/k_env/v1\0";
    /// `HEIMDALL_TEST_KEY_SEED`'s bounds (`heimdall::testcfg`).
    const MAX_SEED_BYTES: usize = 64;

    pub(super) struct TestSeed {
        seed: Zeroizing<Vec<u8>>,
        next: AtomicU64,
    }

    impl TestSeed {
        pub(super) fn new(seed: &[u8]) -> Result<TestSeed, VaultError> {
            if !(1..=MAX_SEED_BYTES).contains(&seed.len()) {
                return Err(VaultError::InvalidSeed);
            }
            Ok(TestSeed {
                seed: Zeroizing::new(seed.to_vec()),
                next: AtomicU64::new(0),
            })
        }

        pub(super) fn next_index(&self) -> u64 {
            self.next.fetch_add(1, Ordering::SeqCst)
        }

        /// `SHA-256(LABEL ‖ u64be(index) ‖ seed)`.
        pub(super) fn derive_into(&self, index: u64, out: &mut [u8; 32]) {
            let mut h = Sha256::new();
            h.update(LABEL);
            h.update(index.to_be_bytes());
            h.update(self.seed.as_slice());
            out.copy_from_slice(&h.finalize());
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn system_rng_fills_distinct_buffers() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        SystemRng::fill(&mut a).unwrap();
        SystemRng.try_fill_bytes(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn slot_hex_round_trips_and_refuses_other_forms() {
        let vault = KeyVault::new();
        let (slot, _) = vault.generate_ed25519().unwrap();
        let hex = slot.to_hex();
        assert_eq!(hex.len(), 32);
        assert_eq!(VaultSlot::from_hex(&hex), Some(slot));
        assert_eq!(VaultSlot::from_hex(&hex.to_uppercase()), None);
        assert_eq!(VaultSlot::from_hex(&hex[1..]), None);
        assert_eq!(VaultSlot::from_hex("zz"), None);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn seeded_vault_derives_the_published_seeds_in_order() {
        let vault = KeyVault::with_test_seed(b"u1-seed").unwrap();
        let (_, first) = vault.generate_ed25519().unwrap();
        let (_, second) = vault.generate_ed25519().unwrap();
        for (index, info) in [(0, first), (1, second)] {
            let seed = seeded_private_key(b"u1-seed", index).unwrap();
            let public = PublicKey::from(Ed25519Keypair::from_seed(&seed).public);
            assert_eq!(public.to_bytes().unwrap(), info.blob);
        }
        assert!(KeyVault::with_test_seed(&[]).is_err());
        assert!(KeyVault::with_test_seed(&[0; 65]).is_err());
    }
}
