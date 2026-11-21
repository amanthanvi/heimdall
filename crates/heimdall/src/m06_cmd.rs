//! M06 command surface, wave 0 (ADR-0012 §2–§5, §9 item 6; m06-plan U0, U2).
//!
//! `env`, `device`, `route`, `transport` and `roost` are registered here (m06-plan §0 rule
//! 1: the integrator owns the subcommand table) and refused until their units land: each is
//! answered with the `USAGE_ERROR` envelope (exit 2, effect `none`, next `fix_request`),
//! built at run time and only here, before the runtime is contacted or the Heimdall home is
//! created. Their arguments are accepted and ignored: the argument trees are the owning
//! units' to design (U2: `env` and `device`; U5a and U5b: `route`, `transport`, `roost`).
//! Each unit replaces its refusal with its handler and its own clap tree.

use heimdall_contract::envelope::Envelope;
use heimdall_contract::{Code, ExitCode};

use crate::client::{Ctx, error};
use crate::output;

/// The message of the refusal, assembled at run time (the M02 and M03 source guards scan
/// for the unassembled text).
pub(crate) fn refusal_message() -> String {
    [
        "this command is not available",
        "in this build (planned for M06)",
    ]
    .join(" ")
}

/// The envelope an M06 command answers until its unit lands.
pub(crate) fn refusal_envelope() -> Envelope<serde_json::Value> {
    output::error_value(error(Code::UsageError, &refusal_message()))
}

/// Print [`refusal_envelope`] and return its exit code. Builds no executor, opens no store
/// and never contacts the runtime. A `--json` among the ignored arguments still selects
/// machine output (the global flag after the command is captured with them).
pub(crate) fn refuse(ctx: &Ctx, args: &crate::cli::PlannedArgs) -> ExitCode {
    let json = ctx.json
        || args
            .args
            .iter()
            .take_while(|a| *a != "--")
            .any(|a| a == "--json");
    let env = refusal_envelope();
    output::emit(&env, json);
    output::exit_code_for(env.code, false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Command, dispatch};

    /// Every M06 command line, with arguments its unit will define (they are accepted and
    /// ignored).
    const LINES: &[&[&str]] = &[
        &["env"],
        &["env", "add", "--destination", "lab", "--account", "runner"],
        &["env", "invite", "env_00", "--role", "viewer"],
        &["env", "join"],
        &["env", "revoke-client", "cl_00"],
        &["env", "remove", "env_00"],
        &["env", "update", "env_00"],
        &["env", "status"],
        &["env", "status", "--json"],
        &["device", "retire"],
        &["route", "add", "lab", "--direct", "10.0.0.1:22"],
        &["route", "remove", "lab", "route_00"],
        &["route", "prefer", "lab", "route_00"],
        &["transport", "enable", "--serve"],
        &["transport", "disable"],
        &["roost", "adopt", "lab", "--endpoint", "00"],
    ];

    /// ADR-0006 §18 (the revision-5 precedent, §17 item 4): each M06 command parses, and
    /// answers `USAGE_ERROR` (exit 2, effect `none`, `fix_request`) with "(planned for
    /// M06)", without creating the Heimdall home (so without starting or contacting a
    /// runtime).
    #[test]
    fn m06_commands_refuse_as_planned_for_m06() {
        let env = refusal_envelope();
        assert_eq!(env.code, Code::UsageError);
        let error = &env.data["error"];
        assert_eq!(error["effect_status"], "none");
        assert_eq!(error["next"]["action"], "fix_request");
        assert_eq!(error["message"], refusal_message());
        assert!(refusal_message().ends_with("(planned for M06)"));
        let scratch = std::env::temp_dir().join(format!("hm-m06-w0-{}", std::process::id()));
        let home = scratch.join("never-created");
        for line in LINES {
            let mut argv = vec!["heimdall", "--json", "--non-interactive", "--home"];
            let home_arg = home.to_str().unwrap();
            argv.push(home_arg);
            argv.extend_from_slice(line);
            let cli = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{line:?}: {e}"));
            assert!(
                matches!(
                    cli.command,
                    Some(
                        Command::Env(_)
                            | Command::Device(_)
                            | Command::Route(_)
                            | Command::Transport(_)
                            | Command::Roost(_)
                    )
                ),
                "{line:?}"
            );
            assert_eq!(dispatch(cli), ExitCode::Usage, "{line:?}");
            assert!(!home.exists(), "{line:?} created the home");
        }
        assert!(!scratch.exists());
    }
}
