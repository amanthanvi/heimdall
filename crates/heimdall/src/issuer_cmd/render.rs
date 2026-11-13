//! Human renderings of the `issuer` results (stdout in human mode; `--json` prints the
//! envelope only). Every string is sanitized by `output::emit_rendered`. Public values
//! only: fingerprints, digests, dates, states and store locators (not secrets).

use std::fmt::Write as _;

use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::{CaState, IssuerStatus, RecoveryBundle};
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
        if registered {
            let _ = writeln!(
                out,
                "\n  displaced by a restore: `heimdall issuer retire {fp}` deletes it once the CA is retired, or rerun the restore"
            );
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
pub(super) fn retired(st: &IssuerStatus, ca: &CaFingerprint) -> String {
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
    out.push_str(&status(st, &[]));
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
