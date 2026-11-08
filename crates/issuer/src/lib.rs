//! Heimdall's issuer (ADR-0008 D1, D3, D4, §18; m03-plan §0.6, U3, U4). Production
//! edges: `contract`, `domain`, `store` (the read-only open), `app`
//! (`issuance_ro`, the `IssuerPort` port), `credential` (certificates,
//! `SecretCaKey`).
//!
//! **Owns:** the `heimdall-issuer/1` protocol ([`protocol`]), the issuer child
//! ([`child`]) and its runtime client and supervision ([`client`]), the loaded CA set
//! ([`ca`]), the reservation check ([`check`]), the K_ca custody interface and its
//! product implementations ([`store`]), the D5 backup ([`backup`]), the ceremonies
//! ([`ceremony`]), retirement ([`retire`]) and the recovery bundle ([`bundle`]). U4
//! adds the one `unsafe` module, `sys.rs` (keychain access lists, DPAPI), with its
//! invariant table in the overview's `unsafe` inventory.
//!
//! **Must not own:** writes to the state database (the issuer opens it read-only and
//! never publishes; publication is the runtime's transaction), K_env or the signer
//! (`heimdall-credential`), a listening endpoint (`EndpointKind::Issuer` is reserved
//! and never bound; ADR-0008 Q1), or any test store (`ScratchSecretStore` lives in
//! `heimdall-testkit`, feature `managed`).
//!
//! **Units.** U0 froze [`protocol`] (the message enums, the 64 KiB framing, the
//! [`protocol::IssuerRefusal`] variants) and the [`store::SecretStore`] trait, and the
//! signature of [`child::run`]. **U3** fills [`child`], [`client`], [`ca`] and
//! [`check`]; **U4** fills the store implementations, [`backup`], [`ceremony`],
//! [`retire`] and [`bundle`]. Until then every body fails closed.

pub mod backup;
pub mod bundle;
pub mod ca;
pub mod ceremony;
pub mod check;
pub mod child;
pub mod client;
pub mod protocol;
pub mod retire;
pub mod store;
