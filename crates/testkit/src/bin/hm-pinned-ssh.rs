//! `hm-pinned-ssh`: the scratch wrapper the debug pinned-client redirect names for
//! `heimdall connect` (ADR-0007 §12.52). What it adds and when it refuses are documented in
//! `heimdall_testkit::pinned_ssh`; this file only calls it.

fn main() {
    std::process::exit(heimdall_testkit::pinned_ssh::main());
}
