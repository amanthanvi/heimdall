//! Boundary 10: a repository's manifest and an import bundle.
#![no_main]
use heimdall_project::{manifest::parse_manifest, parse_bundle};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_manifest(data);
    let _ = parse_bundle(data);
});
