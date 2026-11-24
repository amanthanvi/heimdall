//! ⟨rev7⟩ The skeletons of the commands revision 7 declares before their units land
//! (ADR-0013 §1.3; ADR-0014 §7 H1–H3; the contract owner's rulings on U0-Q7, Q8 and ASK-H3):
//! `support bundle` (H1), `service stop --preview` (H2), `state status|restore|reset|repair`
//! (H3, Q8) and `inspect request <REQUEST_ID>` (Q7).
//!
//! Each answers one envelope, whatever flags it is given: `USAGE_ERROR` (exit 2), effect
//! `none`, next `fix_request`, "this command is not available in this build". It answers
//! before any runtime contact, home creation or file read, and `--json` after the command
//! still selects the envelope. The unit that builds a command replaces its arm in
//! `cli::dispatch`.

use heimdall_contract::envelope::Envelope;
use heimdall_contract::{Code, ExitCode};

use crate::client::{Ctx, error};
use crate::output;

/// The refusal's message, assembled at run time (the earlier milestones' source guards scan
/// for the retired wave-0 text, which this is not: it names no milestone).
fn message() -> String {
    ["this command is not available", "in this build"].join(" ")
}

/// The envelope a declared command answers until its unit lands.
pub(crate) fn envelope() -> Envelope<serde_json::Value> {
    output::error_value(error(Code::UsageError, &message()))
}

/// Print [`envelope`] and return its exit code.
pub(crate) fn not_available(ctx: &Ctx) -> ExitCode {
    let env = envelope();
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, dispatch};

    /// Every declared command line, with flags, answers the envelope and touches nothing:
    /// no runtime directory, no state directory, nothing at all under the Heimdall home it
    /// names (ADR-0014 §7: "every new command answers its not available in this build
    /// envelope until its unit replaces it").
    #[test]
    fn every_declared_command_answers_not_available_and_touches_nothing() {
        let lines: &[&[&str]] = &[
            &["support", "bundle", "--preview"],
            &[
                "support",
                "bundle",
                "--out",
                "bundle.txt",
                "--include-identifiers",
            ],
            &["state", "status"],
            &["state", "restore", "--backup", "state.db.v13.backup"],
            &["state", "reset"],
            &["state", "repair"],
            &["service", "stop", "--preview"],
            &["inspect", "request", "req-0123456789abcdef"],
        ];
        let env = envelope();
        assert_eq!(env.code, Code::UsageError);
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["data"]["error"]["effect_status"], "none");
        assert_eq!(v["data"]["error"]["next"]["action"], "fix_request");
        assert_eq!(v["data"]["error"]["message"], message());
        for line in lines {
            for json in [false, true] {
                let scratch = tempfile::tempdir().unwrap();
                let home = scratch.path().join("home");
                let mut argv = vec!["heimdall".to_owned()];
                if json {
                    argv.push("--json".to_owned());
                }
                argv.extend(["--non-interactive", "--home"].map(str::to_owned));
                argv.push(home.to_string_lossy().into_owned());
                argv.extend(line.iter().map(|a| (*a).to_owned()));
                let cli = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{line:?}: {e}"));
                assert_eq!(dispatch(cli), ExitCode::Usage, "{line:?} json={json}");
                assert!(!home.exists(), "{line:?} created the home");
            }
        }
    }

    /// `inspect` takes an ID only for `request`.
    #[test]
    fn only_inspect_request_takes_an_id() {
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("home");
        let cli = Cli::try_parse_from([
            "heimdall",
            "--json",
            "--home",
            &home.to_string_lossy(),
            "inspect",
            "destinations",
            "extra",
        ])
        .unwrap();
        assert_eq!(dispatch(cli), ExitCode::Usage);
        assert!(!home.exists());
    }
}
