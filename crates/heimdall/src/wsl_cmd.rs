//! M04 command surface, wave 0 (ADR-0010 §9 item 9; m04-plan U0).
//!
//! The clap tree of every M04 command is in `cli.rs`; this module answers the commands the
//! M04 track has not built yet: `wsl enable|disable|status`, `service autostart
//! enable|disable|status`, `service run --login`, `destination add --jump` and the hidden
//! `internal wsl-helper` (`container_cmd` answers `container *`). Each is refused with the
//! `USAGE_ERROR` envelope (exit 2, effect `none`, next `fix_request`), built at run time and
//! only here, before the runtime is contacted or the Heimdall home is created. The track
//! replaces each refusal with its handler and deletes [`refuse`] with the last one.

use heimdall_contract::envelope::Envelope;
use heimdall_contract::{Code, ExitCode};

use crate::client::{Ctx, error};
use crate::output;

/// The message of the refusal, assembled at run time (the M02 and M03 source guards scan
/// for the unassembled text).
pub(crate) fn refusal_message() -> String {
    [
        "this command is not available",
        "in this build (planned for M04)",
    ]
    .join(" ")
}

/// The envelope an M04 command answers until its unit lands.
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
