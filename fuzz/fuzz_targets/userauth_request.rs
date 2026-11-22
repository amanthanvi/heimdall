//! Boundary 6: the userauth purpose parser and the session-bind parser.
#![no_main]
use heimdall_credential::{purpose, session_bind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = purpose::parse_userauth(data);
    let _ = session_bind::parse(data);
});
