//! Boundary 3: an agent's reply to REQUEST_IDENTITIES (256 KiB, 1024 identities).
#![no_main]
use heimdall_ipc::agent_client::parse_reply;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_reply(data, 1024);
});
