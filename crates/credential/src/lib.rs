//! Heimdall's managed credential core (ADR-0008 D1, D2, D6 item 2, §18; m03-plan
//! §0.6, U1, U2). Production edges: `contract`, `domain`, `ipc` (the `Signer` trait,
//! the listeners), `app` (the `SignatureAuthority` and `VerificationEndpoints` ports,
//! `SignPermit`).
//!
//! **Owns:** K_env and K_verify custody ([`vault`]), the certificate profile and the
//! installed-certificate validator ([`cert`], with [`cert::SecretCaKey`]), purpose
//! parsing ([`purpose`]), session-bind ([`session_bind`]), the managed signer
//! ([`signer`]), its endpoints ([`endpoints`]) and the signer table ([`table`]). U1
//! adds the one `unsafe` module, [`sys`] (memory locking and process hardening),
//! with its invariant table in the overview's `unsafe` inventory.
//!
//! **Must not own:** K_ca at rest or the issuer process (`heimdall-issuer`), the
//! authorization decision (`app`, through `SignatureAuthority`), the store, or any
//! enrollment I/O.
//!
//! **Units.** U1 fills [`vault`], [`cert`], [`purpose`], [`session_bind`] and [`sys`];
//! U2 fills [`signer`], [`endpoints`] and [`table`]. Wave 0 (U0) freezes only
//! [`cert::SecretCaKey`], which the issuer's `SecretStore` trait names.

pub mod cert;
pub mod endpoints;
// ⟨M06 U56⟩ K_iroh custody (ADR-0012 §2.4).
pub mod iroh;
// ⟨M06 U2⟩ K_mgmt, the controller's management key (ADR-0012 §3.4).
pub mod mgmt;
pub mod purpose;
// ⟨M06 W5⟩ The debug-build guard between a scratch home and the account's key stores.
pub mod scratch_guard;
pub mod session_bind;
pub mod signer;
// M03-U1: the crate's only `unsafe` module (mlock/VirtualLock, PR_SET_DUMPABLE, RLIMIT_CORE).
pub mod sys;
pub mod table;
pub mod vault;

/// ⟨M06 W5⟩ **Every macOS keychain service name the product can create**, in one place
/// (the login keychain's generic-password items; nothing else of Heimdall's is ever written
/// to a keychain):
///
/// | Service | Account | Item | Store |
/// |---|---|---|---|
/// | `heimdall-mgmt` (exact, [`mgmt::ITEM_SERVICE`]) | the installation's environment ID | K_mgmt | `mgmt::macos` |
/// | `heimdall-iroh` (exact, [`iroh::ITEM_SERVICE`]) | `<environment ID>/<endpoint ID>` | K_iroh | `iroh::macos` |
/// | `heimdall-issuer/<CA fingerprint>` (one per CA; the prefix is [`MACOS_KEYCHAIN_ISSUER_SERVICE_PREFIX`]) | the environment ID, or `<environment ID>#r<n>` for a restore generation | K_ca | `heimdall_issuer::store::macos` |
///
/// The two exact names are this constant. The K_ca service is not one fixed name: a check
/// for it needs each CA fingerprint (`heimdall_issuer::store::item_label`). A check "by
/// service name" over this list and those labels is therefore complete by construction
/// (`heimdall`'s tests pin the issuer's prefix to this one). The values are written out as
/// literals because the native journeys read the list from this file
/// (tests/native/m06/run-crosshost.sh `keychain_services`); the test below pins them to the
/// stores' own constants.
pub const MACOS_KEYCHAIN_SERVICES: [&str; 2] = ["heimdall-mgmt", "heimdall-iroh"];

/// ⟨M06 W5⟩ The prefix of the K_ca items' keychain service (and label); the CA's
/// fingerprint follows (`heimdall_issuer::store::ITEM_LABEL_PREFIX`).
pub const MACOS_KEYCHAIN_ISSUER_SERVICE_PREFIX: &str = "heimdall-issuer/";

#[cfg(test)]
mod keychain_names {
    /// The list is the two exact services, by their own constants' values.
    #[test]
    fn the_macos_keychain_service_list_is_the_two_exact_names() {
        assert_eq!(
            super::MACOS_KEYCHAIN_SERVICES,
            [super::mgmt::ITEM_SERVICE, super::iroh::ITEM_SERVICE]
        );
        assert_eq!(
            super::MACOS_KEYCHAIN_ISSUER_SERVICE_PREFIX,
            "heimdall-issuer/"
        );
    }
}
