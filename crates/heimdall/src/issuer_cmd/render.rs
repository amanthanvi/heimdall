//! Human renderings of the `issuer` results (stdout in human mode; `--json` prints the
//! envelope only). Every string is sanitized by `output::emit_rendered`. Public values
//! only: fingerprints, digests, dates, states and store locators (not secrets).

use std::fmt::Write as _;

use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::{CaState, IssuerState, IssuerStatus, RecoveryBundle};
use heimdall_issuer::ceremony::Registered;

/// The serde name of a public enum value (`snake_case`).
fn word<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "?".to_owned())
}

/// `issuer status` (and the tail of every ceremony).
pub(super) fn status(st: &IssuerStatus, notes: &[String]) -> String {
    let mut out = String::new();
    let _ = write!(out, "issuer: {}", word(&st.state));
    if let Some(r) = &st.reason {
        let _ = write!(out, " ({r})");
        // ⟨ADR-0008 §17.28 item 6⟩ The access-list denial and its recovery.
        if r == heimdall_contract::envelope::reason::ISSUER_STORE_ACCESS_DENIED {
            let _ = write!(
                out,
                "\n{}",
                heimdall_app::issuer::STORE_ACCESS_DENIED_GUIDANCE
            );
        }
    }
    let _ = writeln!(out, "\nboundary: {}", word(&st.issuer_isolation));
    if st.cas.is_empty() {
        let _ = writeln!(
            out,
            "no CA registered: run `heimdall issuer init --backup-out <path>`"
        );
    }
    for c in &st.cas {
        let _ = writeln!(
            out,
            "CA {}  {}  store {}  backup {} (sha256 {})  enrollments: {} verified, {} pending{}",
            c.fingerprint,
            word(&c.state),
            word(&c.store),
            c.backup_created_at,
            c.backup_sha256.get(..16).unwrap_or(&c.backup_sha256),
            c.enrollments.verified,
            c.enrollments.pending,
            if c.restored_without_log {
                "  restored without its log: rotate it"
            } else {
                ""
            },
        );
        match (&c.store_locator, c.state) {
            (Some(l), CaState::Unloaded | CaState::Deleted) => {
                let _ = writeln!(
                    out,
                    "  store item {l} awaits deletion: run `heimdall issuer retire {}`",
                    c.fingerprint
                );
            }
            (Some(l), _) => {
                let _ = writeln!(out, "  store item {l}");
            }
            (None, CaState::Unloaded) => {
                let _ = writeln!(
                    out,
                    "  no store item was recorded: the retirement stays at unloaded (issuer_store_locator_unrecorded)"
                );
            }
            (None, _) => {}
        }
    }
    for o in &st.orphan_store_items {
        let fp = o
            .fingerprint
            .as_ref()
            .map_or_else(|| "(unreadable)".to_owned(), ToString::to_string);
        let registered = o
            .fingerprint
            .as_ref()
            .is_some_and(|f| st.cas.iter().any(|c| c.fingerprint == *f));
        let _ = write!(out, "orphan store item: CA {fp}  store {}", word(&o.store));
        if let Some(l) = &o.locator {
            let _ = write!(out, "  {l}");
        }
        // ⟨§17.31 item 5⟩ Once its CA is retired, no restore is advised.
        let retired = o.fingerprint.as_ref().is_some_and(|f| {
            st.cas
                .iter()
                .any(|c| c.fingerprint == *f && c.state == CaState::Retired)
        });
        if retired {
            let _ = writeln!(
                out,
                "\n  left by a restore of a CA that is now retired: Heimdall deletes it no more; delete it yourself in the store"
            );
        } else if registered {
            let _ = writeln!(
                out,
                "\n  displaced by a restore: `heimdall issuer retire {fp}` deletes it once the CA is retired, or rerun the restore"
            );
        }
        if registered {
            // ⟨ADR-0008 §17.28 item 7⟩ The item a restore after an access-list denial left.
            if o.store == heimdall_contract::issuer::StoreKind::MacosLoginKeychain
                && let Some((service, account)) = o.locator.as_deref().and_then(keychain_parts)
            {
                let _ = writeln!(
                    out,
                    "  if this Heimdall executable cannot read it (issuer_store_access_denied, after an update), Heimdall never deletes it: delete it in Keychain Access (service {service}, account {account})"
                );
            }
        } else {
            let _ = writeln!(
                out,
                "\n  no registration names it: restore it (`heimdall issuer restore --backup <file> --not-stolen`) or replace it (`heimdall issuer init --backup-out <path> --replace-orphan {fp} --bundle <file>`)"
            );
        }
    }
    if st.bundle_stale {
        let _ = writeln!(
            out,
            "recovery bundle: stale (an enrollment changed since the last bundle): run `heimdall issuer bundle --out <path>`"
        );
    }
    for n in notes {
        let _ = writeln!(out, "note: {n}");
    }
    out
}

pub(super) fn lost_device_guidance(st: &IssuerStatus, foreign: bool) -> &'static str {
    let key_unavailable = st.state == IssuerState::StoreUnavailable
        && st.reason.as_deref() != Some(heimdall_contract::envelope::reason::ISSUER_STORE_LOCKED)
        && st
            .cas
            .iter()
            .any(|ca| matches!(ca.state, CaState::Active | CaState::Pending));
    if !key_unavailable && !foreign {
        return "";
    }
    "\nThis installation cannot use the signing key from the device that set up access.\n\
     If you have its encrypted backup and know the device was not stolen, restore the key with:\n  \
       heimdall issuer restore --backup <file> --not-stolen\n\
     To remove that device's trust, use its unredacted recovery bundle on a device that still has access to the machine. Run this once for each entry, using the entry's marker and the alias on this device:\n  \
       heimdall enroll remove --from-bundle <file> --marker <marker> --alias <local alias>\n"
}

#[cfg(test)]
#[test]
fn lost_device_guidance_names_the_restore_and_removal_commands() {
    let mut status = IssuerStatus {
        state: IssuerState::NotInitialized,
        reason: None,
        cas: Vec::new(),
        orphan_store_items: Vec::new(),
        issuer_isolation: heimdall_contract::managed::IssuerIsolation::SameUserProcess,
        bundle_stale: false,
    };
    assert_eq!(lost_device_guidance(&status, false), "");
    let guidance = lost_device_guidance(&status, true);
    assert!(guidance.contains("heimdall issuer restore --backup <file> --not-stolen"));
    assert!(guidance.contains(
        "heimdall enroll remove --from-bundle <file> --marker <marker> --alias <local alias>"
    ));
    status.state = IssuerState::Ready;
    assert_eq!(lost_device_guidance(&status, false), "");
    assert_eq!(lost_device_guidance(&status, true), guidance);
}

/// ⟨ADR-0008 §17.28 item 7⟩ The service and account of a keychain locator
/// (`service=<s>;account=<a>`), or `None` for another form.
pub(super) fn keychain_parts(locator: &str) -> Option<(&str, &str)> {
    let rest = locator.strip_prefix("service=")?;
    let (service, account) = rest.split_once(";account=")?;
    (!service.is_empty() && !account.is_empty()).then_some((service, account))
}

/// A registered CA (init, rotate begin).
pub(super) fn registered(r: &Registered, backup: Option<&str>) -> String {
    let mut out = format!(
        "CA {} registered (decision {}).\n",
        r.fingerprint, r.decision
    );
    if let (Some(b), Some(path)) = (&r.backup, backup) {
        let _ = writeln!(out, "backup: {path} (sha256 {})", b.sha256);
    }
    let _ = writeln!(
        out,
        "Keep the backup file and its passphrase apart, offline, and never in a synchronized folder."
    );
    out
}

/// `issuer retire` finished.
pub(super) fn retired(st: &IssuerStatus, ca: &CaFingerprint, notes: &[String]) -> String {
    let state = st
        .cas
        .iter()
        .find(|c| c.fingerprint == *ca)
        .map_or(CaState::Retired, |c| c.state);
    let mut out = format!("CA {ca}: {}\n", word(&state));
    if state == CaState::Retired {
        let _ = writeln!(
            out,
            "Its store item was deleted. Destroy its offline backup file and passphrase too."
        );
    }
    out.push_str(&status(st, notes));
    out
}

/// `issuer bundle` written.
pub(super) fn bundle(b: &RecoveryBundle, path: &str) -> String {
    let mut out = format!(
        "Recovery bundle written: {path} ({} CA(s), {} enrollment(s); public metadata only).\n",
        b.cas.len(),
        b.enrollments.len()
    );
    if b.redacted {
        let _ = writeln!(
            out,
            "Hostnames are redacted: `heimdall enroll remove --from-bundle` refuses this bundle (bundle_redacted)."
        );
    }
    for i in &b.instructions {
        let _ = writeln!(out, "  {i}");
    }
    out
}
