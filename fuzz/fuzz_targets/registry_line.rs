//! Boundary 7, the registry file's lines: a remote account's authorized_keys content.
#![no_main]
use heimdall_registry::line::{contains, lines, marker_lines, marker_of, marker_ok};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut n = 0usize;
    for l in lines(data) {
        n += l.len();
        if let Ok(text) = std::str::from_utf8(l) {
            if let Some(m) = marker_of(text) {
                let _ = marker_ok(m);
                let _ = marker_lines(data, m);
            }
        }
    }
    let _ = contains(data, b"heimdall");
    let _ = n;
});
