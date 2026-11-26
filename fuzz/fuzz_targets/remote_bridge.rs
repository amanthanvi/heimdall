//! Boundary 13 (ADR-0014 section 2.1): M06's bridge frames, through `heimdall_remote::bridge::serve`.
//! The body is `body/remote_bridge.rs`, which the seed test `tests/adversarial/m08_fuzz_seeds*.rs`
//! also compiles on the pinned stable toolchain.
#![no_main]
#[path = "body/remote_bridge.rs"]
mod body;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = body::run(data);
});
