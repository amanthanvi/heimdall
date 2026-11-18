//! M05 command surface, wave 0 (ADR-0011 §10 item 10; m05-plan U0, U9).
//!
//! The clap tree of every M05 command is in `cli.rs`; this module answers the commands the
//! M05 track has not built yet: `project trust|status|untrust|reconcile`, `access allow` and
//! `access stop`, and the `--profile|--workspace|--all` targets of `access pause|resume|cutoff`
//! (`activate_cmd` answers `activate` and `shell init`, `portable_cmd` `export` and `import`,
//! `delegate_cmd` `run --parent-binding`). Each is refused with the `USAGE_ERROR` envelope
//! (exit 2, effect `none`, next `fix_request`), built at run time and only here, before the
//! runtime is contacted or the Heimdall home is created. The track replaces each refusal
//! with its handler and deletes [`refuse`] with the last one.

use heimdall_contract::envelope::Envelope;
use heimdall_contract::{Code, ExitCode};

use crate::client::{Ctx, error};
use crate::output;

/// The message of the refusal, assembled at run time (the M02 and M03 source guards scan
/// for the unassembled text).
pub(crate) fn refusal_message() -> String {
    [
        "this command is not available",
        "in this build (planned for M05)",
    ]
    .join(" ")
}

/// The envelope an M05 command answers until its unit lands.
pub(crate) fn refusal_envelope() -> Envelope<serde_json::Value> {
    output::error_value(error(Code::UsageError, &refusal_message()))
}

/// Print [`refusal_envelope`] and return its exit code. Builds no executor, opens no
/// store and never contacts the runtime.
pub(crate) fn refuse(ctx: &Ctx) -> ExitCode {
    let env = refusal_envelope();
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}
