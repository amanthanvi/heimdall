//! `hm-fixture-hook`: the fixture hook program for `Match exec`, ProxyCommand and
//! askpass fixtures (m02-plan U7). Modes and exit statuses are documented in
//! `heimdall_testkit::hook`; this file only forwards the arguments.

fn main() {
    let code = heimdall_testkit::hook::main_with_args(std::env::args_os().skip(1).collect());
    std::process::exit(code);
}
