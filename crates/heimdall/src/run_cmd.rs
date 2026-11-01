//! `heimdall run [--profile P] -- <argv>` (m02-plan U8; ADR-0007 §8; spec §10.4).
//!
//! Skeleton (m02-plan U0): until U8 lands, [`run`] answers M01's "not available in
//! this build" envelope and contacts nothing; `argv` is never read. U8 replaces it:
//! `ensure`, `bind(Launch)`, Git resolution, the pre-launch check, then launch
//! through `heimdall_launch`.

use crate::cli::{RunArgs, not_available};
use crate::client::Ctx;
use heimdall_contract::ExitCode;

/// Handle `run`. Wave 0: `USAGE_ERROR` "not available in this build", exit 2.
pub(crate) fn run(ctx: &Ctx, args: RunArgs) -> ExitCode {
    // The argument vector is dropped unread (it never crosses IPC; Q8).
    drop(args);
    not_available(ctx)
}
