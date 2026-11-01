//! The doctor (m02-plan U3; ADR-0007 §6; spec §10.2).
//!
//! The default run is **passive**: the `static` level only, plus local queries unless
//! `--no-local-exec`. It runs no configuration command, contacts no agent, provider or
//! network, and changes nothing. Every other level is explicit and recorded in a
//! `ProbeRecord`. `evaluate`, `host_verification` and `authentication` run the real
//! configuration tree, so without `allow_config_commands` they are always declined
//! (`config_commands_not_authorized`) before anything runs, and a tree the static pass
//! could not fully read declines them even with it (`config_not_fully_readable`).

use std::collections::BTreeSet;
use std::sync::Arc;

use heimdall_contract::doctor::DoctorReport;
use heimdall_contract::provider::ProbeLevel;
use heimdall_sshconf::limits::Limits;

use crate::clients::ClientsConfig;
use crate::env::{Env, Platform};
use crate::local_query::LocalQueries;
use crate::paths::SshPaths;
use crate::probe::ProbeHook;

/// What the doctor runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorRequest {
    /// Levels requested; `static` is always performed.
    pub levels: BTreeSet<ProbeLevel>,
    /// `--allow-config-commands`: the owner's authorization for the real-tree levels.
    pub allow_config_commands: bool,
    /// `--alias`, or every alias when `None`.
    pub aliases: Option<Vec<String>>,
    /// Whether prompts are allowed.
    pub interactive: bool,
    /// `--no-local-exec` turns local queries off.
    pub local_queries: LocalQueries,
    /// `--redact`: display paths and names are redacted in the report.
    pub redact: bool,
}

/// The local facts a doctor run reads.
#[derive(Clone)]
pub struct LocalContext {
    /// SSH configuration locations.
    pub paths: SshPaths,
    /// The environment snapshot.
    pub env: Env,
    /// The platform.
    pub platform: Platform,
    /// `config.toml` `[clients]`.
    pub clients: ClientsConfig,
    /// Read bounds.
    pub limits: Limits,
    /// Test-only probe hook (env-gated through the test configuration; `None` in
    /// production).
    pub probe_hook: Option<Arc<dyn ProbeHook>>,
}

impl std::fmt::Debug for LocalContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalContext")
            .field("platform", &self.platform)
            .field("probe_hook", &self.probe_hook.is_some())
            .finish_non_exhaustive()
    }
}

/// Run the doctor.
#[must_use]
pub fn run(ctx: &LocalContext, request: &DoctorRequest) -> DoctorReport {
    let _ = (ctx, request);
    todo!("M02-U3 doctor::run")
}
