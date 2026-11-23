//! Boundary 11, the advertisement: `instance.json` bytes, as `InstanceInfo::read_file`
//! decodes them after its size bound (64 KiB).
#![no_main]
use heimdall_runtime::instance::InstanceInfo;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<InstanceInfo>(data);
});
