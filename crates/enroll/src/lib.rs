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
//! **Units.** **U5** (wave 1, U5-io) fills [`remote`], [`verify`] and [`trace`]:
//! [`remote::SshStepRunner::run`] runs one step's client with exactly its pins, the
//! ready handshake and the lifetime ties (a Windows run needs the CLI's
//! [`remote::StepContainment`]); [`verify::Verifier`] implements
//! `app::ports::VerificationRunner` (and is unavailable without a client); the trace
//! patterns carry only recorded rows. The third-party edges are already-pinned
//! workspace crates: `tokio`, `async-trait`, `ssh-key`, and on Unix `rustix`
//! (`process`).
//!
//! The crate's one `unsafe` module is `sys` (Linux only; ADR-0008 §17.17 item 5;
//! overview §9 item 7): the `pre_exec` closure that gives a step's child
//! `PR_SET_PDEATHSIG(SIGKILL)`.

pub mod remote;
// ADR-0008 §17.17 item 5: the one `unsafe` module (Linux `PR_SET_PDEATHSIG`).
#[cfg(target_os = "linux")]
mod sys;
pub mod trace;
pub mod verify;
