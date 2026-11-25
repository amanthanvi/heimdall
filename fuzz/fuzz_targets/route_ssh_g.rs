//! Boundary 12: the M06 route checks' `ssh -G` reader, `verify_effective`.
//! The body is `body/route_ssh_g.rs`, which the seed test `tests/adversarial/m08_fuzz_seeds*.rs`
//! also compiles on the pinned stable toolchain.
#![no_main]
#[path = "body/route_ssh_g.rs"]
mod body;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = body::run(data);
});
