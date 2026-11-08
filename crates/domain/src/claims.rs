//! The claim table (ADR-0008 D12 item 3; m03-plan U0, §5 item 16).
//!
//! The **only** source of platform-mechanism claims: `lock_continuity: verified`,
//! `new_signing_expiry: signer`, `owned_multiplexing: closed_at_deadline`, the
//! `existing_connections` behaviour, `new_authentication_expiry: credential_and_signer`,
//! the summary `enforcement.revocation` and `revocation.remote`. A field without a
//! matching entry for this platform and these versions reads `unknown` (or
//! `not_verified` for `lock_continuity`).
//!
//! The table is a static list compiled into the binary. An entry is added only by a
//! reviewed integrator commit after its native evidence record is `verified`
//! (m03-plan §3, "claim update"). `tools/validation/claims_table.py` (the `check.sh`
//! step `claims-table`) parses [`CLAIMS`] from this file's source and fails unless every
//! entry's record exists, validates, is `verified` for that platform row and names a
//! commit that is an ancestor of `HEAD`. It also fails an entry for a custody-dependent
//! field (`lock_continuity`) whose build profile is not `release` or whose store kind
//! is not the platform's product store: test-store evidence never satisfies a
//! product-store claim (F03).
//!
//! **The M03 baseline table is empty.** Keep each entry as one `Claim { … }` struct
//! literal with every field written out, string literals only, so the validator can
//! read it without a Rust parser.

/// The build profile of the run that produced a claim's evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuildProfile {
    /// An optimized release-profile build (the product build).
    Release,
    /// A debug-profile (test-configured) build. Never satisfies a custody claim.
    Debug,
}

/// The platform row a claim covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Platform {
    /// Operating system: `macos`, `linux` or `windows`.
    pub os: &'static str,
    /// Architecture: `aarch64` or `x86_64`.
    pub arch: &'static str,
}

/// An inclusive version range (`min`..=`max`); `max` empty means "no upper bound".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VersionRange {
    /// The lowest version the evidence covers.
    pub min: &'static str,
    /// The highest version the evidence covers, or empty for no upper bound.
    pub max: &'static str,
}

/// One claim-table entry (ADR-0008 D12 item 3, ⟨r2⟩ with build profile and store kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Claim {
    /// The reported field, e.g. `lock_continuity` or `enforcement.revocation`.
    pub field: &'static str,
    /// The value the field may report when this entry matches, e.g. `verified`.
    pub value: &'static str,
    /// The platform and architecture of the run.
    pub platform: Platform,
    /// The OS release floor the evidence covers.
    pub os_floor: &'static str,
    /// The OpenSSH client versions the evidence covers.
    pub client_versions: VersionRange,
    /// The Heimdall signer builds the evidence covers.
    pub signer_builds: VersionRange,
    /// The build profile of the run.
    pub build_profile: BuildProfile,
    /// The secret store kind of the run (`None` when the field does not depend on custody).
    pub store_kind: Option<&'static str>,
    /// The evidence record path, relative to the repository root.
    pub record: &'static str,
    /// The commit at which the record was committed (an ancestor of `HEAD`).
    pub record_commit: &'static str,
}

/// Fields whose claim depends on key custody: an entry for one of them needs a
/// release-profile run on the platform's product store (F03).
pub const CUSTODY_FIELDS: &[&str] = &["lock_continuity"];

/// The platform's product secret store kind, by `Platform::os` (ADR-0008 D1).
/// macOS also accepts `macos_data_protection_keychain`; the validator lists both.
#[must_use]
pub fn product_store_kinds(os: &str) -> &'static [&'static str] {
    match os {
        "macos" => &["macos_login_keychain", "macos_data_protection_keychain"],
        "windows" => &["windows_dpapi"],
        "linux" => &["linux_secret_service"],
        _ => &[],
    }
}

/// The claim table. Empty in the M03 baseline (ADR-0008 D12 item 3).
pub const CLAIMS: &[Claim] = &[];

/// The entries of [`CLAIMS`] for one field and platform.
pub fn claims_for<'a>(
    field: &'a str,
    platform: &'a Platform,
) -> impl Iterator<Item = &'static Claim> + 'a {
    CLAIMS
        .iter()
        .filter(move |c| c.field == field && c.platform == *platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_table_is_empty() {
        assert!(CLAIMS.is_empty());
        let p = Platform {
            os: "macos",
            arch: "aarch64",
        };
        assert_eq!(claims_for("lock_continuity", &p).count(), 0);
        assert_eq!(product_store_kinds("windows"), ["windows_dpapi"]);
        assert!(product_store_kinds("plan9").is_empty());
    }
}
