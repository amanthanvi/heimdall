//! The recovery bundle (ADR-0008 D4 items 4–6; m03-plan U4 `bundle::export`, §5
//! "RecoveryBundle"): `heimdall_contract::issuer::RecoveryBundle` with the CAs, every
//! enrollment (marker, destination ID, alias, hostname and port unless redacted,
//! account, canonical registry, form, state, CA, `line_sha256`, the `late_write`
//! residual) and the removal instructions.
//!
//! It is built **only** from public metadata (the `issuers` rows' public keys,
//! digests and dates; the enrollment records; the catalog's aliases): no input type
//! here can carry a private key, a passphrase or a socket path, so none can reach the
//! bundle. A redacted bundle omits every hostname and port; foreign removal refuses
//! it (`bundle_redacted`).

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

/// The state-store view a bundle is made from (read in one read-only transaction by
/// the caller).
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
