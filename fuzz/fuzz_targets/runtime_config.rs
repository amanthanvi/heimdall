//! Boundary 11: the runtime's configuration file.
#![no_main]
use heimdall_runtime::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Config::parse(text);
    }
});
