#![no_main]
// X3 scratch fuzz target (not part of the frozen prototype). Property: parse_bytes never
// panics (Result is either Ok or Err by construction).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = heimdall_proto::profile::parse_bytes(data);
});
