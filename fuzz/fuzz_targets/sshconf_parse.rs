//! Boundary 1 (ADR-0014 section 2.1): OpenSSH client configuration bytes.
#![no_main]
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::parse::{SourceId, parse_file};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_file(SourceId(0), data, &Limits::default());
});
