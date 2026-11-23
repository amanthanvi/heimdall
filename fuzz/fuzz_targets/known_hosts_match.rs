//! Boundary 12 (the pure part): matching a host name against a known-hosts pattern field.
#![no_main]
use heimdall_localenv::known_hosts::{hosts_match, lookup_name};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (hosts, name) = text.split_once('\n').unwrap_or((text, "box.example.invalid"));
    let _ = hosts_match(hosts, name);
    let _ = lookup_name(name, 22);
});
