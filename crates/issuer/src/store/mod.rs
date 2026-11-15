//! The K_ca custody store interface (ADR-0008 D1, D3 item 3; F23). **Frozen in wave 0**
//! (m03-plan U0 owns this file; U4 implements it).
//!
//! The issuer reads its CA keys only through [`SecretStore`]. The product
//! implementations (macOS login keychain, Windows DPAPI, Linux Secret Service) are
//! U4's, in `store/{macos,windows,linux}.rs`. The test implementation,
//! `ScratchSecretStore`, lives in `heimdall-testkit` (feature `managed`) and reports a
//! [`SecretStoreKind::Test`] kind: the public `StoreKind` has **no** test variant, so
//! fixture custody can never appear in the public schema or satisfy a product-store
//! claim (ADR-0008 D12).
//!
//! Rules every implementation follows (ADR-0008 D1):
//! * **No plaintext fallback**, ever: an unavailable store is an error, never a file.
//! * The issuer never triggers a store prompt; interaction is disallowed on reads, and
//!   a store that would need it reports [`StoreAvailability::InteractionNotAllowed`].
//! * Items are labelled [`item_label`] (`heimdall-issuer/<fingerprint>`) and carry the
//!   environment ID attribute; deletion is by exact identity ([`StoreItemRef`]).

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::StoreKind;
use heimdall_credential::cert::SecretCaKey;
use serde::{Deserialize, Serialize};

// M03-U4: the product implementations (ADR-0008 D1), and the environment-scoped logic of
// the attribute-addressed store (§17.17 item 3; wave-1 review W1-R01).
pub mod attributes;
// M03-U4: the product implementations (ADR-0008 D1).
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;
// ⟨ADR-0008 §17.25 item 7 (b)⟩ Debug builds only: the test configuration's disposable
// store of a product kind (`HEIMDALL_TEST_SECRET_STORE=product-file:<abs path>`).
#[cfg(debug_assertions)]
pub mod test_product;
#[cfg(target_os = "linux")]
pub use linux::LinuxSecretService;
#[cfg(target_os = "macos")]
pub use macos::MacosLoginKeychain;
#[cfg(windows)]
pub use windows::WindowsDpapi;
// M03-U4: the key type the trait names, for implementors whose crate does not depend
// on heimdall-credential directly (the e2e ceremony suite's test store).
pub use heimdall_credential::cert::SecretCaKey as StoredCaKey;

/// The prefix of every store item's label.
pub const ITEM_LABEL_PREFIX: &str = "heimdall-issuer/";

/// The label of the store item holding the CA `fingerprint`.
#[must_use]
pub fn item_label(fingerprint: &CaFingerprint) -> String {
    format!("{ITEM_LABEL_PREFIX}{}", fingerprint.as_str())
}

/// A store's availability (ADR-0008 D1 "Store availability"). Anything but
/// [`StoreAvailability::Available`] makes the issuer unavailable. The wire form (the
/// `heimdall-issuer/1` `store_unavailable` reason) is snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StoreAvailability {
    /// The store can be read without interaction.
    Available,
    /// The store is locked.
    Locked,
    /// A read would need user interaction, which the issuer never allows (macOS
    /// `errSecInteractionNotAllowed`).
    InteractionNotAllowed,
    /// The store (or its service) is absent.
    Missing,
    /// The store answered with data that does not decode.
    Corrupt,
    /// No product store exists here (headless Linux, WSL, a container, a runner).
    Unsupported,
    /// ⟨ADR-0008 §17.28 item 6⟩ The store is unlocked, but the item's access list does
    /// not trust this executable, so the CA key cannot be read (macOS
    /// `errSecAuthFailed` from an **unlocked** keychain: the item trusts the creating
    /// executable's code identity, which an ad-hoc-signed build changes with every
    /// update). Unlocking cannot help; the recovery is the log-intact restore. Only an
    /// item read reports it, never [`SecretStore::availability`].
    AccessDenied,
}

impl StoreAvailability {
    /// Every value, in ADR-0008 D1's order (then ⟨§17.28 item 6⟩ `access_denied`).
    pub const ALL: [StoreAvailability; 7] = [
        StoreAvailability::Available,
        StoreAvailability::Locked,
        StoreAvailability::InteractionNotAllowed,
        StoreAvailability::Missing,
        StoreAvailability::Corrupt,
        StoreAvailability::Unsupported,
        StoreAvailability::AccessDenied,
    ];

    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StoreAvailability::Available => "available",
            StoreAvailability::Locked => "locked",
            StoreAvailability::InteractionNotAllowed => "interaction_not_allowed",
            StoreAvailability::Missing => "missing",
            StoreAvailability::Corrupt => "corrupt",
            StoreAvailability::Unsupported => "unsupported",
            StoreAvailability::AccessDenied => "access_denied",
        }
    }

    /// The `CAPABILITY_UNAVAILABLE` sub-reason for an unavailable store
    /// (`issuer_store_locked` when an owner unlock can help; ⟨§17.28 item 6⟩
    /// `issuer_store_access_denied` when the access list denied this executable, which
    /// no unlock can help; else `issuer_store_unavailable`); `None` when available.
    #[must_use]
    pub fn refusal_reason(self) -> Option<&'static str> {
        match self {
            StoreAvailability::Available => None,
            StoreAvailability::Locked | StoreAvailability::InteractionNotAllowed => {
                Some(reason::ISSUER_STORE_LOCKED)
            }
            StoreAvailability::Missing
            | StoreAvailability::Corrupt
            | StoreAvailability::Unsupported => Some(reason::ISSUER_STORE_UNAVAILABLE),
            StoreAvailability::AccessDenied => Some(reason::ISSUER_STORE_ACCESS_DENIED),
        }
    }
}

/// The kind of a [`SecretStore`]: a product kind from the public schema, or a
/// test-configuration kind named by `heimdall-testkit` (F23). Test kinds never
/// satisfy a product-store claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SecretStoreKind {
    /// A product store.
    Product(StoreKind),
    /// A test-configuration store; the name is the testkit's (`scratch_test`).
    Test(&'static str),
}

impl SecretStoreKind {
    /// The product kind, when this is one.
    #[must_use]
    pub fn product(self) -> Option<StoreKind> {
        match self {
            SecretStoreKind::Product(kind) => Some(kind),
            SecretStoreKind::Test(_) => None,
        }
    }
}

/// The exact identity of one store item: what `delete` removes, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreItemRef {
    /// The store it lives in.
    pub kind: SecretStoreKind,
    /// The CA it holds.
    pub fingerprint: CaFingerprint,
    /// The store-specific exact identity (keychain service and account, the DPAPI
    /// blob's path, the Secret Service item path, the scratch file). Not a secret.
    pub locator: String,
}

/// A store operation's failure. Messages carry no item content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The store is not available (never [`StoreAvailability::Available`]).
    #[error("the secret store is unavailable ({})", .0.as_str())]
    Unavailable(StoreAvailability),
    /// No item holds that CA.
    #[error("no store item holds that CA")]
    NotFound,
    /// An item for that CA already exists (`put` never overwrites).
    #[error("a store item for that CA already exists")]
    AlreadyExists,
    /// The item exists but does not decode to the CA it is labelled with.
    #[error("the store item is corrupt")]
    Corrupt,
    /// The store refused the operation for another reason.
    #[error("the secret store refused the operation")]
    Failed,
    /// ⟨M03 wave 5, round 3⟩ The item's access list would trust an executable that is not
    /// the running program: the file at this program's path was replaced (an update, a
    /// rebuild) after it started. Nothing was written: the item would trust the new file,
    /// and this process could never read it back.
    ///
    /// ⟨ADR-0008 §17.28 item 5⟩ Reason `issuer_executable_changed`
    /// ([`StoreError::refusal_reason`]), `SERVICE_UNAVAILABLE` (retryable).
    #[error(
        "Heimdall's executable was replaced while this command ran (an update?), so the CA key store item would not trust the running program: nothing was stored; finish installing or updating Heimdall, then run the command again"
    )]
    ExecutableChanged,
}

impl StoreError {
    /// The stable sub-reason of this failure, when it has one: the availability's
    /// ([`StoreAvailability::refusal_reason`]) or ⟨§17.28 item 5⟩
    /// `issuer_executable_changed`.
    #[must_use]
    pub fn refusal_reason(&self) -> Option<&'static str> {
        match self {
            StoreError::Unavailable(a) => a.refusal_reason(),
            StoreError::ExecutableChanged => Some(reason::ISSUER_EXECUTABLE_CHANGED),
            _ => None,
        }
    }
}

/// The K_ca custody store (ADR-0008 D1; F23). Implementations are synchronous and
/// bounded; the issuer child calls them from its single request loop.
pub trait SecretStore: Send + Sync {
    /// The store's kind.
    fn kind(&self) -> SecretStoreKind;

    /// The store's current availability, read without user interaction.
    fn availability(&self) -> StoreAvailability;

    /// Store `key` for `fingerprint`. Never overwrites an existing item
    /// ([`StoreError::AlreadyExists`]) and never falls back to plaintext.
    fn put(
        &self,
        fingerprint: &CaFingerprint,
        key: &SecretCaKey,
    ) -> Result<StoreItemRef, StoreError>;

    /// Read the CA key for `fingerprint`, without user interaction.
    fn get(&self, fingerprint: &CaFingerprint) -> Result<SecretCaKey, StoreError>;

    /// Delete exactly `item` (by its exact identity; never by pattern).
    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError>;

    /// Every Heimdall item **of this installation** in the store (labels with
    /// [`ITEM_LABEL_PREFIX`]), for the orphan report and uninstall. ⟨§17.17 item 3;
    /// wave-1 review W1-R01, W1-R02⟩ A store the OS user shares across installations
    /// (the keychain, the Secret Service, the DPAPI directory) lists only this
    /// installation's items, so nothing here ever names another installation's item.
    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError>;

    /// ⟨ADR-0008 §17.28 item 7⟩ Read exactly `item` (an item of this installation, by its
    /// recorded locator), without user interaction. [`StoreError::NotFound`] when `item`
    /// names no item of this installation in this store.
    ///
    /// Additive (defaulted, so no implementor changes): a store whose items have one
    /// locator per CA reads by fingerprint, as [`SecretStore::get`].
    fn get_item(&self, item: &StoreItemRef) -> Result<SecretCaKey, StoreError> {
        if item.kind != self.kind() {
            return Err(StoreError::NotFound);
        }
        self.get(&item.fingerprint)
    }

    /// ⟨ADR-0008 §17.28 item 7⟩ Store `key` for `fingerprint` in a **new** item whose
    /// locator differs from every existing item's: the restore after an
    /// `issuer_store_access_denied` read, when the recorded item can no longer be read
    /// (or deleted) by this executable. Never overwrites, never deletes; refused
    /// ([`StoreError::AlreadyExists`]) when no free locator is left.
    ///
    /// Additive (defaulted): a store without per-executable access lists never reports
    /// that denial, and refuses this ([`StoreError::Failed`]).
    fn put_new_item(
        &self,
        fingerprint: &CaFingerprint,
        key: &SecretCaKey,
    ) -> Result<StoreItemRef, StoreError> {
        let _ = (fingerprint, key);
        Err(StoreError::Failed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn availability_wire_names_and_reasons() {
        let names: Vec<&str> = StoreAvailability::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(
            names,
            [
                "available",
                "locked",
                "interaction_not_allowed",
                "missing",
                "corrupt",
                "unsupported",
                "access_denied"
            ]
        );
        for a in StoreAvailability::ALL {
            let json = serde_json::to_string(&a).unwrap();
            assert_eq!(json, format!("\"{}\"", a.as_str()));
            assert_eq!(serde_json::from_str::<StoreAvailability>(&json).unwrap(), a);
        }
        assert_eq!(StoreAvailability::Available.refusal_reason(), None);
        assert_eq!(
            StoreAvailability::InteractionNotAllowed.refusal_reason(),
            Some(reason::ISSUER_STORE_LOCKED)
        );
        assert_eq!(
            StoreAvailability::Unsupported.refusal_reason(),
            Some(reason::ISSUER_STORE_UNAVAILABLE)
        );
    }

    /// ⟨ADR-0008 §17.28 items 5, 6⟩ An access-list denial is its own reason, never the
    /// lock's; a replaced executable is `issuer_executable_changed`.
    #[test]
    fn access_denied_and_executable_changed_have_their_own_reasons() {
        assert_eq!(
            StoreAvailability::AccessDenied.refusal_reason(),
            Some(reason::ISSUER_STORE_ACCESS_DENIED)
        );
        assert_eq!(
            StoreError::Unavailable(StoreAvailability::AccessDenied).refusal_reason(),
            Some(reason::ISSUER_STORE_ACCESS_DENIED)
        );
        for locked in [
            StoreAvailability::Locked,
            StoreAvailability::InteractionNotAllowed,
        ] {
            assert_eq!(locked.refusal_reason(), Some(reason::ISSUER_STORE_LOCKED));
        }
        assert_eq!(
            StoreError::ExecutableChanged.refusal_reason(),
            Some(reason::ISSUER_EXECUTABLE_CHANGED)
        );
        assert_eq!(StoreError::Failed.refusal_reason(), None);
        assert!(
            StoreError::ExecutableChanged
                .to_string()
                .contains("finish installing or updating Heimdall, then run the command again")
        );
    }

    #[test]
    fn test_kinds_are_not_product_kinds() {
        assert_eq!(SecretStoreKind::Test("scratch_test").product(), None);
        assert_eq!(
            SecretStoreKind::Product(StoreKind::WindowsDpapi).product(),
            Some(StoreKind::WindowsDpapi)
        );
        let fp = CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap();
        assert_eq!(
            item_label(&fp),
            format!("heimdall-issuer/SHA256:{}", "A".repeat(43))
        );
    }
}
