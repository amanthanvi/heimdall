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
pub mod purpose;
pub mod session_bind;
pub mod signer;
// M03-U1: the crate's only `unsafe` module (mlock/VirtualLock, PR_SET_DUMPABLE, RLIMIT_CORE).
pub mod sys;
pub mod table;
pub mod vault;
