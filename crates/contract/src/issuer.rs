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
    },
    /// Attended sessions only. kind `issuer.unlock`.
    Unlock,
    /// Creates a `RetireIssuer` decision. kind `issuer.retire`.
    Retire {
        /// The CA to retire.
        ca_fingerprint: CaFingerprint,
    },
    /// Read-only; public metadata only. kind `issuer.bundle`; data
    /// [`RecoveryBundle`].
    Bundle {
        /// Omit hostnames (foreign removal then refuses the bundle).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        redact_hostnames: bool,
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
}

/// A store item no registration names (ADR-0008 D4 item 1 crash points).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrphanStoreItem {
    /// Its key's fingerprint, when readable without unlocking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<CaFingerprint>,
    /// Store kind.
    pub store: StoreKind,
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
}
