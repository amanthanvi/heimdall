//! `heimdall`: one binary for the CLI, the TUI entry point and the per-user
//! runtime (`heimdall service run`). Spec §11.1 command surface; §11.6 exit codes;
//! §10.4 process contract for `run`.
//!
//! No banners or JSON on protocol stdout; diagnostics go to stderr (spec §10.4).
//! Machine output is the envelope only. Nothing here authorizes access: every
//! command goes through `heimdall_app::Operations`, locally in `service run` or
//! over the authenticated control endpoint otherwise.

mod cli;
mod output;

use clap::Parser;

fn main() -> std::process::ExitCode {
    let args = cli::Cli::parse();
    let code = cli::dispatch(args);
    code.into()
}
