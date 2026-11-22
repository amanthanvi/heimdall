//! K_iroh's source (ADR-0012 §2.4). The transport never stores a key: it asks a
//! [`KeySource`] for the 32 secret bytes when it builds an endpoint, and wipes its copy on
//! drop. The platform-store implementations (macOS Keychain, Windows DPAPI, Secret Service)
//! and the K_iroh lifecycle (generate at enable, rotate, destroy at disable) are m06-plan
//! U56's. Never a plaintext or owner-only file (spec §7.3).

use heimdall_contract::envelope::reason;
use zeroize::Zeroizing;

/// K_iroh's 32 secret bytes, wiped on drop. Its `Debug` never prints them.
#[derive(Clone)]
pub struct IrohSecret(Zeroizing<[u8; 32]>);

impl IrohSecret {
    /// Wraps secret bytes (the caller's copy is its own to wipe).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// A fresh random K_iroh (ephemeral unless a store keeps it).
    #[cfg(feature = "iroh")]
    #[must_use]
    pub fn generate() -> Self {
        Self::from_bytes(iroh::SecretKey::generate().to_bytes())
    }

    /// The endpoint ID this key authenticates as.
    #[cfg(feature = "iroh")]
    #[must_use]
    pub fn endpoint_id(&self) -> Option<heimdall_contract::ids::IrohEndpointId> {
        crate::endpoint::contract_id(&self.secret_key().public())
    }

    #[cfg(feature = "iroh")]
    pub(crate) fn secret_key(&self) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&self.0)
    }
}

impl std::fmt::Debug for IrohSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IrohSecret(..)")
    }
}

/// Why K_iroh could not be loaded. Every variant answers `CAPABILITY_UNAVAILABLE` with
/// `transport_key_store_unavailable` (ADR-0012 §2.4 items 3 and 4); the variant is the
/// doctor detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySourceError {
    /// No verified platform store on this host (headless Linux today).
    StoreUnavailable,
    /// The store is locked.
    Locked,
    /// No K_iroh in the store (transport not enabled, or the key was lost: a rotation).
    Missing,
    /// The stored item is not a 32-byte key.
    Corrupt,
}

impl KeySourceError {
    /// The stable reason token.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        reason::TRANSPORT_KEY_STORE_UNAVAILABLE
    }
}

impl std::fmt::Display for KeySourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self {
            Self::StoreUnavailable => "no verified key store",
            Self::Locked => "key store locked",
            Self::Missing => "no transport key in the store",
            Self::Corrupt => "stored transport key is malformed",
        };
        write!(f, "{}: {what}", self.reason())
    }
}

impl std::error::Error for KeySourceError {}

/// Where K_iroh comes from. Implementations may block briefly (a store query); the
/// transport calls [`KeySource::load`] once per endpoint, before it binds.
pub trait KeySource: Send + Sync {
    /// Loads K_iroh.
    ///
    /// # Errors
    ///
    /// [`KeySourceError`] when no key can be produced; the endpoint is then unavailable.
    fn load(&self) -> Result<IrohSecret, KeySourceError>;
}

/// A key held in memory only: tests and container fixtures (mechanism evidence, never
/// product persistence; m06-plan U56). It persists nothing.
#[derive(Debug, Clone)]
pub struct InMemoryKeySource(IrohSecret);

impl InMemoryKeySource {
    /// Holds `secret`.
    #[must_use]
    pub fn new(secret: IrohSecret) -> Self {
        Self(secret)
    }

    /// Holds a freshly generated key.
    #[cfg(feature = "iroh")]
    #[must_use]
    pub fn generate() -> Self {
        Self(IrohSecret::generate())
    }
}

impl KeySource for InMemoryKeySource {
    fn load(&self) -> Result<IrohSecret, KeySourceError> {
        Ok(self.0.clone())
    }
}

/// A source that never has a key (the no-verified-store host).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoKeyStore;

impl KeySource for NoKeyStore {
    fn load(&self) -> Result<IrohSecret, KeySourceError> {
        Err(KeySourceError::StoreUnavailable)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn key_source_errors_answer_transport_key_store_unavailable() {
        for e in [
            KeySourceError::StoreUnavailable,
            KeySourceError::Locked,
            KeySourceError::Missing,
            KeySourceError::Corrupt,
        ] {
            assert_eq!(e.reason(), "transport_key_store_unavailable");
            assert!(
                e.to_string()
                    .starts_with("transport_key_store_unavailable: ")
            );
        }
        assert_eq!(
            NoKeyStore.load().unwrap_err(),
            KeySourceError::StoreUnavailable
        );
    }

    #[cfg(feature = "iroh")]
    #[test]
    fn in_memory_source_returns_its_key_and_debug_redacts() {
        let source = InMemoryKeySource::generate();
        let a = source.load().unwrap();
        let b = source.load().unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_eq!(a.endpoint_id(), b.endpoint_id());
        assert!(a.endpoint_id().is_some());
        assert_eq!(format!("{a:?}"), "IrohSecret(..)");
        assert!(!format!("{source:?}").contains(&format!("{:?}", a.expose())));
        assert_ne!(
            InMemoryKeySource::generate().load().unwrap().expose(),
            a.expose()
        );
    }
}
