//! Login autostart of the per-user runtime (M04 U1; ADR-0010 §1 items 1, 2 and 7, §6;
//! m04-plan U1).
//!
//! One platform file per registration mechanism, selected by `target_os`. Wave 0 holds the
//! registration only; the M04 track fills the platform files.

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;
