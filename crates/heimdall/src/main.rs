//! `heimdall`: one binary for the CLI, the TUI entry point and the per-user
//! runtime (`heimdall service run`). Spec §11.1 command surface; §11.6 exit codes;
//! §10.4 process contract for `run`.
//!
//! No banners or JSON on protocol stdout; diagnostics go to stderr (spec §10.4).
//! Machine output is the envelope only. Nothing here authorizes access: every
//! command goes through `heimdall_app::Operations`, locally in `service run` or
//! over the authenticated control endpoint otherwise.

mod catalog_cmd;
mod cli;
mod client;
mod connect_cmd;
mod connections_cmd;
mod doctor_cmd;
mod enroll_cmd;
mod issuer_cmd;
mod launch_flow;
mod m03_cmd;
mod output;
mod prompt;
mod run_cmd;
mod service_cmd;
mod setup_cmd;
mod testcfg;
mod tui;
mod uninstall_cmd;

use clap::Parser;

fn main() -> std::process::ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let args = match cli::Cli::try_parse_from(&argv) {
        Ok(a) => a,
        Err(e) => {
            // Help and version are successes; every other parse failure is a
            // usage error (exit 2, ADR-0006 §6), one `USAGE_ERROR` envelope on
            // stdout when `--json` was requested (spec §11.2; review C01).
            return cli::parse_failure(&e, cli::json_requested(&argv)).into();
        }
    };
    let code = cli::dispatch(args);
    code.into()
}
