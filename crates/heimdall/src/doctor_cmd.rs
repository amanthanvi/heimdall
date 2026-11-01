//! `heimdall doctor` (m02-plan U9; ADR-0007 §6).
//!
//! Skeleton (m02-plan U0): until U9 lands, [`run`] answers M01's "not available in
//! this build" envelope and runs nothing. U9 replaces it with the passive doctor
//! (`heimdall_localenv::doctor::run`), which never starts the runtime and reads
//! the store read-only.

use crate::cli::{DoctorArgs, not_available};
use crate::client::Ctx;
use heimdall_contract::ExitCode;

/// Handle `doctor`. Wave 0: `USAGE_ERROR` "not available in this build", exit 2.
pub(crate) fn run(ctx: &Ctx, args: DoctorArgs) -> ExitCode {
    drop(args);
    not_available(ctx)
}
