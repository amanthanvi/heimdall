//! ⟨M03⟩ The issuer request handling's public surface (m03-plan U10; ADR-0008 D3,
//! D4) and the issuer child's lifecycle port.
//!
//! The store-backed handling (`issuer.register`, `unlock`, `retire`, `status`,
//! `bundle`, and the completion of the `RegisterIssuer` and `RetireIssuer`
//! decisions) is `crate::operations::issuer_m03`, entered through
//! [`crate::Operations::issuer_request`]. This module holds the pure parts: the
//! lifecycle port, the recovery bundle builder ([`bundle`]), and the checks the
//! handling applies ([`ca_public_key_fingerprint`], [`retire_admissible`],
//! [`enrollment_counts`], [`register_disclosures`], [`unlock_guidance`]).

use async_trait::async_trait;
use heimdall_contract::enrollment::{DisclosureKind, EnrollmentState};
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{CaFingerprint, EnrollmentId};
use heimdall_contract::issuer::EnrollmentCounts;
use heimdall_domain::enrollment::EnrollmentRecord;

use crate::ports::IssuerError;

/// The issuer child's lifecycle (ADR-0008 D3 items 6–7), beside the frozen
/// [`crate::ports::IssuerPort`]: implemented by `heimdall_issuer::client::ChildIssuer`
/// (through the runtime), driven by the runtime's start and stop order and by
/// `issuer.unlock` / the `RegisterIssuer` completion.
///
/// Drop contract: a dropped future leaves no child half-started; `stop` fences every
/// restart of the stopped lifecycle (ADR-0008 §17.19 item 3).
#[async_trait]
pub trait IssuerLifecycle: Send + Sync {
    /// Start the child (loading every `active`/`pending` CA the store records).
    ///
    /// # Errors
    /// [`IssuerError`].
    async fn start(&self) -> Result<(), IssuerError>;

    /// Reload the CA set from the platform store (`issuer unlock`; the
    /// `RegisterIssuer` completion). Starts the child when none runs.
    ///
    /// # Errors
    /// [`IssuerError`].
    async fn reload(&self) -> Result<(), IssuerError>;

    /// Stop the child (zeroizing every CA it holds); idempotent.
    async fn stop(&self);
}

/// The length of an Ed25519 OpenSSH public-key blob: `string "ssh-ed25519"` (4 + 11)
/// and `string key` (4 + 32).
const ED25519_BLOB_LEN: usize = 51;

/// ADR-0008 D4 item 1 step 3: the `SHA256:` fingerprint of a registration's
/// `ca_public_key`, which must be exactly one OpenSSH **Ed25519** public key line
/// with no comment (`ssh-ed25519 <base64>`). `None` for anything else.
#[must_use]
pub fn ca_public_key_fingerprint(line: &str) -> Option<CaFingerprint> {
    use base64ct::Encoding as _;
    let mut fields = line.split(' ');
    let (kind, blob) = (fields.next()?, fields.next()?);
    if kind != "ssh-ed25519" || fields.next().is_some() || blob.is_empty() {
        return None;
    }
    let decoded = base64ct::Base64::decode_vec(blob).ok()?;
    if decoded.len() != ED25519_BLOB_LEN {
        return None;
    }
    let fp = crate::issuance_ro::subject_fingerprint(line)?;
    CaFingerprint::parse(&fp).ok()
}

/// Whether `digest` is a hex SHA-256 (64 lowercase hex characters), as
/// `backup_sha256` must be.
#[must_use]
pub fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// ADR-0008 D4 item 3 (§17.1 item 7): a CA may be retired only when every enrollment
/// under it is final or `abandoned`. `Ok` carries the abandoned ones, sorted (their
/// lines stay, `pending_until_line_removed`; the `RetireIssuer` decision lists them);
/// `Err` every enrollment that is neither, sorted.
///
/// # Errors
/// The open enrollments.
pub fn retire_admissible(
    ca: &CaFingerprint,
    enrollments: &[EnrollmentRecord],
) -> Result<Vec<EnrollmentId>, Vec<EnrollmentId>> {
    let (mut open, mut abandoned) = (Vec::new(), Vec::new());
    for e in enrollments.iter().filter(|e| e.ca_fingerprint == *ca) {
        if e.state == EnrollmentState::Abandoned {
            abandoned.push(e.id.clone());
        } else if !e.state.is_final() {
            open.push(e.id.clone());
        }
    }
    open.sort();
    abandoned.sort();
    if open.is_empty() {
        Ok(abandoned)
    } else {
        Err(open)
    }
}

/// The `issuer.status` counts of a CA's enrollments: `verified`, and `pending`
/// (neither final, `verified` nor `abandoned`).
#[must_use]
pub fn enrollment_counts(ca: &CaFingerprint, enrollments: &[EnrollmentRecord]) -> EnrollmentCounts {
    let mut counts = EnrollmentCounts::default();
    for e in enrollments.iter().filter(|e| e.ca_fingerprint == *ca) {
        match e.state {
            EnrollmentState::Verified => counts.verified = counts.verified.saturating_add(1),
            EnrollmentState::Abandoned => {}
            s if s.is_final() => {}
            _ => counts.pending = counts.pending.saturating_add(1),
        }
    }
    counts
}

/// The disclosures a `RegisterIssuer` decision carries (ADR-0008 D4 item 1 step 3):
/// the same-user issuer boundary, the blast radius, the backup instructions, lock
/// continuity **once** (only while it was never acknowledged, R-UX-03, D9 item 1), and
/// for a key-only restore that every residual is unknown (D4 item 4).
#[must_use]
pub fn register_disclosures(
    restored_without_log: bool,
    lock_disclosure_acknowledged: bool,
) -> Vec<DisclosureKind> {
    let mut out = vec![
        DisclosureKind::SameUserIssuerBoundary,
        DisclosureKind::CaTrustBlastRadius,
    ];
    if !lock_disclosure_acknowledged {
        out.push(DisclosureKind::LockContinuityOnce);
    }
    out.push(DisclosureKind::BackupInstructions);
    if restored_without_log {
        out.push(DisclosureKind::RestoredWithoutLogResidualsUnknown);
    }
    out
}

/// ⟨§17.17 item 10, U4-Q2(b)⟩ What `issuer unlock` tells the owner when the platform
/// store is not available: Heimdall never shows a store prompt, so the owner unlocks
/// the store in the desktop session and asks again. `None` for a reason that is not a
/// store reason.
#[must_use]
pub fn unlock_guidance(reason_code: &str) -> Option<&'static str> {
    match reason_code {
        reason::ISSUER_STORE_LOCKED => Some(
            "the platform secret store is locked or would need a prompt, which Heimdall never shows: unlock it in the desktop session (the login keychain on macOS, the login collection of the Secret Service on Linux, the user's logon session on Windows), then run `heimdall issuer unlock` again",
        ),
        reason::ISSUER_STORE_UNAVAILABLE => Some(
            "the platform secret store is unavailable or does not hold the registered CA: check that the desktop session's store is running and holds this installation's item (`heimdall issuer status` lists orphan items); restore the CA from its backup if the item was lost",
        ),
        _ => None,
    }
}

pub mod bundle {
    //! The recovery bundle (ADR-0008 D4 items 4–6; m03-plan U4 `bundle::export`, §5
    //! "RecoveryBundle"): `heimdall_contract::issuer::RecoveryBundle` with the CAs,
    //! every enrollment (marker, destination ID, alias, hostname and port unless
    //! redacted, account, canonical registry, form, state, CA, `line_sha256`, the
    //! `late_write` residual) and the removal instructions.
    //!
    //! It is built **only** from public metadata (the `issuers` rows' public keys,
    //! digests and dates; the enrollment records; the catalog's aliases): no input type
    //! here can carry a private key, a passphrase or a socket path, so none can reach
    //! the bundle. A redacted bundle omits every hostname and port; foreign removal
    //! refuses it (`bundle_redacted`).
    //!
    //! ⟨M03 wave 4⟩ Moved here from `heimdall_issuer::bundle` (which re-exports it) so
    //! that `issuer.bundle` (`Operations::issuer_request`) builds it in the runtime:
    //! `heimdall-issuer` depends on `heimdall-app`, not the reverse.

    use heimdall_contract::Timestamp;
    use heimdall_contract::enrollment::EnrollmentForm;
    use heimdall_contract::ids::CaFingerprint;
    use heimdall_contract::issuer::{
        BundleCa, BundleEnrollment, BundleLateWrite, RECOVERY_BUNDLE_SCHEMA, RecoveryBundle,
    };
    use heimdall_domain::enrollment::EnrollmentRecord;
    use heimdall_store::IssuerRecord;

    /// What a bundle omits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    #[non_exhaustive]
    pub enum Redaction {
        /// Nothing: hostnames and ports are included (foreign removal needs them).
        #[default]
        None,
        /// Hostnames and ports are omitted (`--redact hostnames`).
        Hostnames,
    }

    /// One enrollment and the catalog alias of its destination.
    #[derive(Debug, Clone, Copy)]
    pub struct EnrollmentEntry<'a> {
        /// The record.
        pub record: &'a EnrollmentRecord,
        /// The destination's alias in this installation's catalog.
        pub alias: &'a str,
    }

    /// The state-store view a bundle is made from (read in one read-only transaction
    /// by the caller).
    #[derive(Debug, Clone, Copy)]
    pub struct StoreView<'a> {
        /// When the bundle is written.
        pub created_at: Timestamp,
        /// Every registered CA (retired ones included).
        pub cas: &'a [IssuerRecord],
        /// Every enrollment, with its alias.
        pub enrollments: &'a [EnrollmentEntry<'a>],
    }

    /// A bundle cannot be made.
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    #[non_exhaustive]
    pub enum BundleError {
        /// An enrollment names a CA that is not registered.
        #[error("an enrollment names an unregistered CA")]
        UnknownCa(CaFingerprint),
    }

    /// The removal instructions every bundle carries.
    fn instructions(redacted: bool) -> Vec<String> {
        let mut out = vec![
            "This file holds public metadata only: CA public keys, fingerprints, backup digests and enrollment records. It holds no private key, passphrase or socket path.".to_owned(),
            "To remove an account-form enrollment's line from another device that has existing access to the account: heimdall enroll remove --from-bundle <this file> --marker <marker> --alias <that device's alias for the destination>.".to_owned(),
            "The line is rebuilt from the CA public key, the principal and the marker and checked against line_sha256 before anything connects; the alias's HostName and Port must equal the bundle's hostname and port exactly.".to_owned(),
            "System-form enrollments are never removed by Heimdall: remove the CA's line from the server's TrustedUserCAKeys file and the account's principal from its AuthorizedPrincipalsFile, as the server's administrator.".to_owned(),
            "Destroy a CA's offline backup only after that CA is retired and no line trusts it.".to_owned(),
        ];
        if redacted {
            out.push(
                "This bundle is redacted (no hostnames or ports): foreign removal refuses it (bundle_redacted). Keep an unredacted bundle for recovery.".to_owned(),
            );
        }
        out
    }

    /// Build the recovery bundle from `view`, redacting as `redact` says.
    ///
    /// # Errors
    /// [`BundleError::UnknownCa`] when an enrollment's CA is not in `view.cas` (the
    /// store's foreign key makes that impossible for a consistent view).
    pub fn export(view: &StoreView<'_>, redact: Redaction) -> Result<RecoveryBundle, BundleError> {
        let redacted = redact == Redaction::Hostnames;
        let cas: Vec<BundleCa> = view
            .cas
            .iter()
            .map(|c| BundleCa {
                fingerprint: c.ca_fingerprint.clone(),
                public_key: c.public_key.clone(),
                backup_sha256: c.backup_sha256.clone(),
                backup_created_at: c.backup_created_at,
                state: c.state,
            })
            .collect();
        let mut enrollments = Vec::with_capacity(view.enrollments.len());
        for entry in view.enrollments {
            let r = entry.record;
            let ca = view
                .cas
                .iter()
                .find(|c| c.ca_fingerprint == r.ca_fingerprint)
                .ok_or_else(|| BundleError::UnknownCa(r.ca_fingerprint.clone()))?;
            enrollments.push(BundleEnrollment {
                marker: r.marker.clone(),
                destination_id: r.destination.as_str().to_owned(),
                alias: entry.alias.to_owned(),
                hostname: (!redacted).then(|| r.target.hostname.clone()),
                port: (!redacted).then_some(r.target.port),
                account: r.account.clone(),
                registry: r.registry_canonical.clone(),
                registry_path_display: r.registry.path_display.clone(),
                form: r.form,
                state: r.state,
                ca_fingerprint: r.ca_fingerprint.clone(),
                ca_public_key: ca.public_key.clone(),
                line_sha256: r.line_sha256.clone(),
                late_write: r.late_write.as_ref().map(|l| BundleLateWrite {
                    not_after_remote: l.not_after_remote,
                }),
            });
        }
        enrollments.sort_by(|a, b| a.marker.cmp(&b.marker));
        let has_system = enrollments.iter().any(|e| e.form == EnrollmentForm::System);
        let mut instructions = instructions(redacted);
        if !has_system {
            instructions.retain(|i| !i.starts_with("System-form"));
        }
        Ok(RecoveryBundle {
            schema: RECOVERY_BUNDLE_SCHEMA.to_owned(),
            created_at: view.created_at,
            redacted,
            cas,
            enrollments,
            instructions,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ca_public_key_must_be_one_ed25519_line_without_comment() {
        // A syntactically valid Ed25519 blob (type string + 32 zero bytes).
        use base64ct::Encoding as _;
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[7u8; 32]);
        let b64 = base64ct::Base64::encode_string(&blob);
        let line = format!("ssh-ed25519 {b64}");
        let fp = ca_public_key_fingerprint(&line).unwrap();
        assert!(fp.as_str().starts_with("SHA256:"));
        assert_eq!(
            crate::issuance_ro::subject_fingerprint(&line).as_deref(),
            Some(fp.as_str())
        );
        assert!(ca_public_key_fingerprint(&format!("{line} comment")).is_none());
        assert!(ca_public_key_fingerprint(&format!("ssh-rsa {b64}")).is_none());
        assert!(ca_public_key_fingerprint(&format!("{line}\n")).is_none());
        assert!(ca_public_key_fingerprint("ssh-ed25519 AAAA").is_none());
        assert!(is_sha256_hex(&"ab".repeat(32)));
        assert!(!is_sha256_hex(&"AB".repeat(32)));
        assert!(!is_sha256_hex("ab"));
    }

    #[test]
    fn lock_continuity_is_disclosed_once() {
        assert!(register_disclosures(false, false).contains(&DisclosureKind::LockContinuityOnce));
        assert!(!register_disclosures(false, true).contains(&DisclosureKind::LockContinuityOnce));
        assert!(
            register_disclosures(true, true)
                .contains(&DisclosureKind::RestoredWithoutLogResidualsUnknown)
        );
        assert!(unlock_guidance(reason::ISSUER_STORE_LOCKED).is_some());
        assert!(unlock_guidance(reason::ISSUER_UNAVAILABLE).is_none());
    }
}
