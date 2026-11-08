//! `heimdall enroll <destination>` and `enroll status|verify|remove|reconcile|abandon`
//! (m03-plan §5 item 24; ADR-0008 D5).
//!
//! Wave 0: the argument tree is in `cli.rs`. The CLI process is the only reader of
//! `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` (the client-executed remote steps pause there,
//! U5), so the command first checks the test configuration: a release build that
//! sees the variable exits 2 before anything else, and a debug build validates it.
//! Then every form answers the wave-0 envelope of [`crate::m03_cmd`] before any
//! runtime contact (U12 fills the bodies).

use heimdall_contract::{Code, ExitCode};

use crate::cli::EnrollArgs;
use crate::client::{Ctx, error};
use crate::m03_cmd;
use crate::output;
use crate::testcfg;

/// Handle `enroll`.
pub(crate) fn run(ctx: &Ctx, args: EnrollArgs) -> ExitCode {
    if let Err(msg) = testcfg::enroll_hooks(&|n| std::env::var_os(n)) {
        let env = output::error_value(error(Code::UsageError, &msg));
        output::emit(&env, ctx.json);
        return output::exit_code_for(env.code, false);
    }
    // `enroll` alone names neither a destination nor a subcommand.
    if args.command.is_none() && args.start.destination.is_none() {
        let env = output::error_value(error(
            Code::UsageError,
            "enroll needs a destination or a subcommand",
        ));
        output::emit(&env, ctx.json);
        return output::exit_code_for(env.code, false);
    }
    m03_cmd::not_available(ctx)
}
