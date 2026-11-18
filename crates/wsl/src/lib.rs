//! Heimdall's WSL realization (M04; ADR-0010 §2–§3; m04-plan).
//!
//! **Owns:** WSL distribution discovery (ADR-0010 §2), the `heimdall-wsl/1` helper channel
//! between the Windows runtime and the in-distribution helper (`heimdall internal
//! wsl-helper`), and the two realization modes, Mode A and Mode B (ADR-0010 §3).
//!
//! * [`proto`]: the frames, framing, wire mirrors and the checks Windows makes before it
//!   persists what the helper sends (pure);
//! * [`discover`]: Lxss entries and the running set (pure);
//! * [`helper`]: the helper process (Linux);
//! * [`client`]: the Windows side of a session, and the projection writer and cleaner of one
//!   distribution (`DistributionWriter`, `DistributionCleaner`);
//! * [`spawn`]: the `wsl.exe` commands and bounded runs;
//! * [`host`]: `WslHost`, the `DistributionHost` port's implementation.
//!
//! **Must not be imported by:** `heimdall-app`. This crate implements `app` ports and the
//! runtime wires it (`heimdall-runtime → heimdall-wsl`); the crate-graph step refuses an
//! `app → wsl` edge (`tools/validation/crate_graph.py`).
//!
//! **Mode B** (the Linux-native scoped endpoint) is a later unit's: its frames are defined
//! in [`proto`] and the helper answers them `unsupported`.

pub mod client;
pub mod discover;
pub mod helper;
pub mod host;
pub mod proto;
pub mod spawn;

pub use client::{
    DistributionCleaner, DistributionWriter, HelperLauncher, HelperSession, SessionError, Transport,
};
pub use host::{DirectLauncher, WslExeLauncher, WslHost};

#[cfg(all(test, unix))]
mod channel_tests;

#[cfg(all(test, windows))]
mod windows_tests;
