//! Heimdall's enrollment I/O (ADR-0008 D5 §6.3, §6.5, §18; m03-plan §0.6, U5).
//! Production edges: `contract`, `domain`, `registry` (the scripts, HM1, the
//! classification), `app` (the `VerificationRunner` port). **I/O only**: every
//! protocol decision is `heimdall-registry`'s.
//!
//! **Owns:** the CLI-side runner of client-executed remote steps ([`remote`]), the
//! runtime-side production verification ([`verify`]) and the client trace patterns
//! ([`trace`]).
//!
//! **Must not own:** the remote protocol, the scripts or the classification
//! (`heimdall-registry`), the journal or the enrollment state machine (`app`,
//! `domain`), K_verify or its endpoint (`heimdall-credential`, through
//! `VerificationEndpoints`), or the runtime itself (the runtime never runs the
//! existing-access `ssh`; ADR-0008 D5 §6.3).
//!
//! **Units.** **U5** fills [`remote`], [`verify`] and [`trace`]. Wave 0 (U0) gives the
//! skeletons: [`remote::SshStepRunner::run`] refuses without spawning anything, and
//! [`verify::Verifier`] implements no port.

pub mod remote;
pub mod trace;
pub mod verify;
