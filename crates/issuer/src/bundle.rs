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
//!
//! ⟨M03 wave 4 (U10)⟩ The builder lives in `heimdall_app::issuer::bundle`, so the
//! runtime's `issuer.bundle` request builds exactly this bundle (`heimdall-app` cannot
//! depend on this crate); it is re-exported here unchanged.

pub use heimdall_app::issuer::bundle::{
    BundleError, EnrollmentEntry, Redaction, StoreView, export,
};
