//! Boundary 13: M06's invitation state, a paired client's join decided by `decide_join`.
//! The body is `body/remote_join.rs`, which the seed test `tests/adversarial/m08_fuzz_seeds*.rs`
//! also compiles on the pinned stable toolchain.
#![no_main]
#[path = "body/remote_join.rs"]
mod body;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = body::run(data);
});
