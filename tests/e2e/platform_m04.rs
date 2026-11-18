//! ⟨M04⟩ The M04 platform suite (m04-plan U1, U2): the real binary's login-entry commands on
//! every host, and the native Windows integration on Windows. One target with platform-gated
//! modules, so every host runs at least one of its tests (`tools/validation/check.sh`'s
//! test discovery refuses a target that runs none).
//!
//! * [`service_login`]: `service run --login`, `service autostart`, uninstall's login-entry
//!   seam (U1; every host).
//! * `windows`: inherited-handle lists, the A14 non-takeover inventory and the Git client
//!   finding (U2; Windows only).
//! * `wsl_cli`: `wsl enable|disable|status` on a host without WSL (U3b; every host but
//!   Windows).
//! * `container`: the container recipe's mounted flow (U5; Linux only; its engine rows skip
//!   by name without `HEIMDALL_M04_CONTAINER_ENGINE`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    missing_docs
)]

#[path = "service_login_m04.rs"]
mod service_login;

#[cfg(windows)]
#[path = "windows_m04.rs"]
mod windows;

#[cfg(not(windows))]
#[path = "wsl_cli_m04.rs"]
mod wsl_cli;

#[cfg(target_os = "linux")]
#[path = "container_m04.rs"]
mod container;
// `exit_m03/world.rs`, which the container module includes, names `crate::procs`.
#[cfg(target_os = "linux")]
use container::procs;
