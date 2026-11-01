//! `heimdall tui` (m02-plan U10).
//!
//! Skeleton (m02-plan U0): until U10 lands, [`run`] answers M01's "not available in
//! this build" envelope and touches no terminal state. U10 replaces it with
//! `tui::run(TuiConfig)`: Ratatui on the main thread, IPC on a worker thread.

use crate::cli::not_available;
use crate::client::Ctx;
use heimdall_contract::ExitCode;

/// Handle `tui`. Wave 0: "not available in this build", exit 2.
pub(crate) fn run(ctx: &Ctx) -> ExitCode {
    not_available(ctx)
}
