//! Boundary 7: the remote registry's HM1 record and holder record.
#![no_main]
use heimdall_registry::classify::HolderRecord;
use heimdall_registry::hm1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hm1::parse(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = HolderRecord::parse(text);
    }
});
