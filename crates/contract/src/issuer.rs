//! ⟨M03⟩ `Request::Issuer`, the issuer status and the recovery bundle (ADR-0006
//! revision 4; m03-plan §5 item 2 and "RecoveryBundle"; ADR-0008 D3, D4).
//!
//! Public metadata only: a CA **public** key, fingerprints, digests and dates. No
//! type here carries a private key, a passphrase or a socket path.

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::enrollment::{EnrollmentForm, EnrollmentState, RegistryCanonical};
use crate::ids::{AccountName, CaFingerprint};
use crate::managed::IssuerIsolation;

/// `Request::Issuer`, tagged `action` (capability `issuer/1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum IssuerRequest {
    /// Read-only. kind `issuer.status`; data [`IssuerStatus`].
    Status,
    /// Effectful, synchronous; always creates a `RegisterIssuer` decision and never
    /// executes on dispatch (ADR-0006 §2.3 N04 pattern). kind `issuer.register`.
    /// Covers init, rotate-begin and restore.
    Register {
        /// OpenSSH one-line Ed25519 public key, no comment.
        ca_public_key: String,
        /// The store the key will live in.
        store: StoreKind,
        /// Hex SHA-256 of the exact D5 backup bytes prepared in memory before this
        /// request; the bytes are written only after approval (ADR-0008 D4 item 1).
        backup_sha256: String,
        /// When the backup bytes were prepared.
        backup_created_at: Timestamp,
        /// Rotate-begin: the CA this one rotates.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rotation_of: Option<CaFingerprint>,
        /// A key-only restore (ADR-0008 D4 item 4).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        restored_without_log: bool,
        /// ⟨ADR-0008 §17.22 item 12⟩ The ceremony's report of the K_ca store item it
        /// wrote: the exact `StoreItemRef` locator its `put` returned (D4 item 1 step
        /// 6), bound to this CA, this installation and `store`. Sent again after the
        /// put with the same registration: it joins the pending `RegisterIssuer`
        /// decision, which records it, and the approval records it with the CA.
        /// Absent before the put (step 3).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        store_locator: Option<String>,
        /// ⟨ADR-0008 §17.22 item 12⟩ A restore that wrote a new store item for a CA
        /// whose record survives (D4 item 4, log intact; a re-registration of the
        /// known CA): the locator it expects recorded now, compared and swapped for
        /// `store_locator` on approval (absent: none recorded). A mismatch refuses and
        /// changes nothing. The displaced item is listed in `orphan_store_items`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_store_locator: Option<String>,
    },
    /// Attended sessions only. kind `issuer.unlock`.
    Unlock,
    /// Creates a `RetireIssuer` decision. kind `issuer.retire`. On a CA whose
    /// retirement waits at `unloaded`, answers the issuer status, which names the
    /// store item to delete ([`CaStatus::store_locator`]).
    Retire {
        /// The CA to retire.
        ca_fingerprint: CaFingerprint,
        /// ⟨ADR-0008 §17.22 item 12⟩ The owner-present CLI's confirmation that it
        /// deleted exactly this store item and a re-read found it absent (attended
        /// sessions only): the CA's recorded locator while it is `unloaded` (the
        /// record then reaches `retired`), or one of its displaced items listed in
        /// `orphan_store_items` (it leaves the list). Anything else is refused and
        /// changes nothing. The runtime never deletes a store item itself (D3).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deleted_locator: Option<String>,
    },
    /// Read-only; public metadata only. kind `issuer.bundle`; data
    /// [`RecoveryBundle`].
    Bundle {
        /// Omit hostnames (foreign removal then refuses the bundle).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        redact_hostnames: bool,
    },
    /// ⟨ADR-0008 §17.25 item 8⟩ The CLI's confirmation that it wrote a recovery
    /// bundle completely and fsynced it. kind `issuer.bundle_written`; synchronous
    /// (it records `last_bundle_at` and the digest, which never lower). The record
    /// never stores the file's path. Sent only after the write; a bundle the CLI
    /// failed to write is never confirmed.
    BundleWritten {
        /// The written bundle's `created_at` (`RecoveryBundle::created_at`).
        created_at: Timestamp,
        /// Hex SHA-256 of the exact bytes written (lowercase, 64 characters; the
        /// form of `Register.backup_sha256`).
        sha256: String,
    },
}

impl IssuerRequest {
    /// The request kind (`issuer.<action>`).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            IssuerRequest::Status => "issuer.status",
            IssuerRequest::Register { .. } => "issuer.register",
            IssuerRequest::Unlock => "issuer.unlock",
            IssuerRequest::Retire { .. } => "issuer.retire",
            IssuerRequest::Bundle { .. } => "issuer.bundle",
            IssuerRequest::BundleWritten { .. } => "issuer.bundle_written",
        }
    }
}

/// The platform store holding K_ca (ADR-0008 D1). **No test variant**: the
/// test-only store kind lives in `heimdall-testkit`, outside the public schema
/// (F23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StoreKind {
    /// The macOS login keychain.
    MacosLoginKeychain,
    /// The macOS data-protection keychain.
    MacosDataProtectionKeychain,
    /// Windows DPAPI (current user).
    WindowsDpapi,
    /// The Linux Secret Service.
    LinuxSecretService,
}

/// The issuer's state (§5 item 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IssuerState {
    /// No CA registered.
    NotInitialized,
    /// The child is starting.
    Starting,
    /// The child is loading keys.
    Loading,
    /// Ready.
    Ready,
    /// The store is unavailable (with `reason`).
    StoreUnavailable,
    /// The child crashed.
    Crashed,
    /// Unavailable.
    Unavailable,
    /// Stopping.
    Stopping,
}

/// A CA's state (ADR-0008 D4 item 3). Transitions:
/// `heimdall_domain::issuance::ca_transition`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CaState {
    /// Rotation's new CA before its first verified enrollment; signs only
    /// verification certificates for its own enrollments.
    Pending,
    /// Issues for pairs it has a verified enrollment for.
    Active,
    /// Issuance disabled; the key is being unloaded.
    Retiring,
    /// No process holds the key.
    Unloaded,
    /// The store item is gone.
    Deleted,
    /// Final.
    Retired,
}

impl CaState {
    /// Every state, in D4 item 3's order.
    pub const ALL: [CaState; 6] = [
        CaState::Pending,
        CaState::Active,
        CaState::Retiring,
        CaState::Unloaded,
        CaState::Deleted,
        CaState::Retired,
    ];
}

/// Per-CA enrollment counts.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct EnrollmentCounts {
    /// `verified` enrollments.
    pub verified: u32,
    /// Enrollments not yet final, verified or abandoned.
    pub pending: u32,
}

/// One registered CA in the issuer status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CaStatus {
    /// Fingerprint.
    pub fingerprint: CaFingerprint,
    /// State.
    pub state: CaState,
    /// Store kind.
    pub store: StoreKind,
    /// Backup digest (hex).
    pub backup_sha256: String,
    /// Backup time.
    pub backup_created_at: Timestamp,
    /// A key-only restore.
    pub restored_without_log: bool,
    /// Enrollment counts.
    pub enrollments: EnrollmentCounts,
    /// ⟨ADR-0008 §17.22 item 12⟩ The CA's K_ca store item as this installation
    /// recorded it (the locator the ceremony reported). While `state` is `unloaded`
    /// the retirement waits for the owner-present CLI to delete exactly this item and
    /// confirm it (`issuer.retire` with `deleted_locator`). Absent when none was
    /// recorded: that retirement stops at `unloaded`, `issuer_store_locator_unrecorded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_locator: Option<String>,
}

/// A store item no registration names (ADR-0008 D4 item 1 crash points), or
/// ⟨§17.22 item 12⟩ one a restore displaced: listed until the owner-present CLI
/// deletes it and confirms (`issuer.retire` with `deleted_locator`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrphanStoreItem {
    /// Its key's fingerprint, when readable without unlocking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<CaFingerprint>,
    /// Store kind.
    pub store: StoreKind,
    /// ⟨§17.22 item 12⟩ Its exact locator, when known (a displaced item: the locator
    /// recorded before the restore's compare-and-swap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

/// `issuer.status` data and `inspect issuer` (§5 item 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IssuerStatus {
    /// Issuer state.
    pub state: IssuerState,
    /// With `store_unavailable`: why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Registered CAs.
    pub cas: Vec<CaStatus>,
    /// Orphan store items.
    pub orphan_store_items: Vec<OrphanStoreItem>,
    /// The issuer boundary.
    pub issuer_isolation: IssuerIsolation,
    /// The last recovery bundle predates an enrollment change.
    pub bundle_stale: bool,
}

/// The recovery bundle's schema tag.
pub const RECOVERY_BUNDLE_SCHEMA: &str = "heimdall-recovery-bundle/1";

/// One CA in a recovery bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BundleCa {
    /// Fingerprint.
    pub fingerprint: CaFingerprint,
    /// The OpenSSH public key.
    pub public_key: String,
    /// Backup digest (hex).
    pub backup_sha256: String,
    /// Backup time.
    pub backup_created_at: Timestamp,
    /// State.
    pub state: CaState,
}

/// A bundle enrollment's `late_write` residual: the remote not-after only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BundleLateWrite {
    /// Remote epoch seconds after which a late script fails its own check.
    pub not_after_remote: i64,
}

/// One enrollment in a recovery bundle (public metadata).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BundleEnrollment {
    /// `heimdall:enr_…`.
    pub marker: String,
    /// The writing installation's destination ID (a label elsewhere).
    pub destination_id: String,
    /// The alias.
    pub alias: String,
    /// Hostname; absent in a redacted bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Port; absent in a redacted bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Account.
    pub account: AccountName,
    /// The canonical registry (what foreign removal uses).
    pub registry: RegistryCanonical,
    /// For people only; never parsed back.
    pub registry_path_display: String,
    /// Form.
    pub form: EnrollmentForm,
    /// State.
    pub state: EnrollmentState,
    /// CA.
    pub ca_fingerprint: CaFingerprint,
    /// The CA's OpenSSH public key.
    pub ca_public_key: String,
    /// The line's SHA-256 (hex).
    pub line_sha256: String,
    /// The `late_write` residual, while it exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_write: Option<BundleLateWrite>,
}

/// `issuer.bundle` data: a file written only by the CLI (§5 "RecoveryBundle").
/// Never a private key, a passphrase or a socket path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecoveryBundle {
    /// [`RECOVERY_BUNDLE_SCHEMA`].
    pub schema: String,
    /// When written.
    pub created_at: Timestamp,
    /// Hostnames omitted.
    pub redacted: bool,
    /// CAs.
    pub cas: Vec<BundleCa>,
    /// Enrollments.
    pub enrollments: Vec<BundleEnrollment>,
    /// Removal instructions.
    pub instructions: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn store_kind_has_no_test_variant() {
        let schema = serde_json::to_string(&schemars::schema_for!(StoreKind)).unwrap();
        assert!(!schema.contains("scratch"), "{schema}");
        let r: Result<StoreKind, _> = serde_json::from_str("\"scratch_test\"");
        assert!(r.is_err());
    }

    #[test]
    fn issuer_request_wire_forms() {
        let r: IssuerRequest = serde_json::from_str(r#"{"action":"status"}"#).unwrap();
        assert_eq!(r.kind(), "issuer.status");
        let b: IssuerRequest = serde_json::from_str(r#"{"action":"bundle"}"#).unwrap();
        assert_eq!(
            b,
            IssuerRequest::Bundle {
                redact_hostnames: false
            }
        );
    }

    /// ⟨ADR-0008 §17.22 item 12⟩ The additive store-item fields: absent in the old
    /// shapes (which decode and re-encode byte-identically), present when given.
    #[test]
    fn issuer_store_item_fields_are_additive() {
        let fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let old_retire = format!(r#"{{"action":"retire","ca_fingerprint":"{fp}"}}"#);
        let r: IssuerRequest = serde_json::from_str(&old_retire).unwrap();
        assert!(matches!(
            &r,
            IssuerRequest::Retire {
                deleted_locator: None,
                ..
            }
        ));
        assert_eq!(serde_json::to_string(&r).unwrap(), old_retire);
        let confirm = format!(
            r#"{{"action":"retire","ca_fingerprint":"{fp}","deleted_locator":"/org/fixture/1"}}"#
        );
        let r: IssuerRequest = serde_json::from_str(&confirm).unwrap();
        assert!(matches!(
            &r,
            IssuerRequest::Retire { deleted_locator: Some(l), .. } if l == "/org/fixture/1"
        ));
        assert_eq!(serde_json::to_string(&r).unwrap(), confirm);

        let old_register = r#"{"action":"register","ca_public_key":"ssh-ed25519 AAAA","store":"windows_dpapi","backup_sha256":"11","backup_created_at":"2026-11-10T14:00:00Z"}"#;
        let r: IssuerRequest = serde_json::from_str(old_register).unwrap();
        assert!(matches!(
            &r,
            IssuerRequest::Register {
                store_locator: None,
                expected_store_locator: None,
                ..
            }
        ));
        assert_eq!(serde_json::to_string(&r).unwrap(), old_register);
        let report = r#"{"action":"register","ca_public_key":"ssh-ed25519 AAAA","store":"windows_dpapi","backup_sha256":"11","backup_created_at":"2026-11-10T14:00:00Z","store_locator":"new","expected_store_locator":"old"}"#;
        let r: IssuerRequest = serde_json::from_str(report).unwrap();
        assert!(matches!(
            &r,
            IssuerRequest::Register { store_locator: Some(n), expected_store_locator: Some(o), .. }
                if n == "new" && o == "old"
        ));
        assert_eq!(serde_json::to_string(&r).unwrap(), report);

        let old_orphan = r#"{"store":"linux_secret_service"}"#;
        let o: OrphanStoreItem = serde_json::from_str(old_orphan).unwrap();
        assert_eq!(o.locator, None);
        assert_eq!(serde_json::to_string(&o).unwrap(), old_orphan);
    }
}
