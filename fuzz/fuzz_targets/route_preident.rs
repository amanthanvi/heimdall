//! Boundary 14: the route helper's pre-identification buffer, `scan_identification`.
//! The body is `body/route_preident.rs`, which the seed test `tests/adversarial/m08_fuzz_seeds*.rs`
//! also compiles on the pinned stable toolchain.
#![no_main]
#[path = "body/route_preident.rs"]
mod body;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = body::run(data);
});
