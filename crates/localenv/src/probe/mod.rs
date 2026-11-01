//! Explicit probes (m02-plan U3; ADR-0007 §6).
//!
//! Each probe has a timeout and runs its children in their own process group (Unix,
//! `killpg` through `sys`) or a kill-on-close job object without breakaway (Windows,
//! `sys`). Each fills `ProbeRecord.{authorization, executed_config_commands,
//! effects_excluded, containment, config_tree_changed, config_tree_differences}`
//! exactly as ADR-0007 §6 states. `executed_config_commands` holds what the static
//! pass found **before** the run and is never described as complete.
//!
//! The level functions take a [`ProbeContext`] and return their [`ProbeRecord`]; the
//! level-specific observations a unit needs beyond the record are U3's to add.

use std::time::Duration;

use heimdall_contract::doctor::ProbeRecord;
use heimdall_contract::provider::ProbeLevel;

use crate::doctor::LocalContext;

pub mod agent;
pub mod auth;
pub mod evaluate;
pub mod host;
pub mod network;
pub mod snapshot;

/// The default per-level bound.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The test-only hook points (never compiled into a release build's request paths;
/// env-gated through the test configuration, like `ReplaceHook`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbePoint {
    /// Between the static pass and the start of the `ssh` child.
    AfterStaticPass,
}

/// A test-only hook run at a [`ProbePoint`].
pub trait ProbeHook: Send + Sync {
    /// Called at `point` for `level`.
    fn at(&self, point: ProbePoint, level: ProbeLevel);
}

/// What every level gets.
#[derive(Debug, Clone)]
pub struct ProbeContext<'a> {
    /// The local facts.
    pub local: &'a LocalContext,
    /// `--allow-config-commands`.
    pub allow_config_commands: bool,
    /// Whether prompts are allowed.
    pub interactive: bool,
    /// The level's bound.
    pub timeout: Duration,
}

/// Build the record of a level declined before anything ran.
#[must_use]
pub fn declined(level: ProbeLevel, target: &str, reason: &'static str) -> ProbeRecord {
    let _ = (level, target, reason);
    todo!("M02-U3 probe::declined")
}
