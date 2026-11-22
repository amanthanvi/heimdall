//! Boundary 5: signing-endpoint request payloads.
#![no_main]
use heimdall_ipc::signing::{SessionBindRecord, classify, parse_sign_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = classify(data);
    let _ = parse_sign_request(data);
    let _ = SessionBindRecord::parse(data);
});
