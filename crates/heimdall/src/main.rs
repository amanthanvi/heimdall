//! `heimdall`: one binary for the CLI, the TUI entry point and the per-user
//! runtime (`heimdall service run`). Spec §11.1 command surface; §11.6 exit codes;
//! §10.4 process contract for `run`.
//!
//! No banners or JSON on protocol stdout; diagnostics go to stderr (spec §10.4).
//! Machine output is the envelope only. Nothing here authorizes access: every
//! command goes through `heimdall_app::Operations`, locally in `service run` or
//! over the authenticated control endpoint otherwise.

// ⟨M08 U3c⟩ The test configuration (`testcfg`, the scratch stores, the fake sources) needs the
// test kit, which a release build never has: a debug build without the default feature
// `test-config` is not a supported configuration.
#[cfg(all(debug_assertions, not(feature = "test-config")))]
compile_error!(
    "a debug build of heimdall needs the default feature `test-config`; a release build is built with --no-default-features"
);

mod activate_cmd;
mod catalog_cmd;
mod cli;
mod client;
mod connect_cmd;
mod connections_cmd;
mod container_cmd;
// ⟨M05⟩ U8: `run --parent-binding` (ADR-0011 §6).
mod delegate_cmd;
// ⟨M05⟩ W3 (ruling I-15): the debug-build guard against the account's real home.
mod dev_home_guard;
mod doctor_cmd;
mod enroll_cmd;
// ⟨M05⟩ W4 (review M05-W4-R02): opening a user-named input file without ever waiting on it.
mod input_file;
mod issuer_cmd;
mod launch_flow;
mod m03_cmd;
// ⟨M05⟩ U9a (ADR-0011 §2–§7): `project`, `access allow|stop|default-profile` and the
// targets of `access pause|resume|cutoff`.
mod m05_cmd;
// ⟨M06⟩ `environment` and `device` (U2); `route` and `transport`, refused until U56 lands.
mod m06_cmd;
mod output;
mod portable_cmd;
mod prompt;
// ⟨ADR-0008 §17.33 items 4-5⟩ The purge's anchored deletion.
mod purge_sweep;
// ⟨rev7⟩ The skeletons of revision 7's declared commands (ADR-0013 §1.3; ADR-0014 H1–H3).
mod rev7_cmd;
mod run_cmd;
// ⟨M05⟩ U9a: `run` without `--profile` (ADR-0011 §3.2, §5.3).
mod run_m05;
mod service_cmd;
mod setup_cmd;
mod testcfg;
mod tui;
mod uninstall_cmd;
// ⟨M04⟩ joint wave 0 (ADR-0010 §9 item 9): refusals until the M04 handlers land.
mod wsl_cmd;

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
