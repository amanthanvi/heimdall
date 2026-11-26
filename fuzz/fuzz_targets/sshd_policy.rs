//! Boundary 13: the `sshd -T` verifier, `heimdall_remote::sshd_policy::verify`.
//! The body is `body/sshd_policy.rs`, which the seed test `tests/adversarial/m08_fuzz_seeds*.rs`
//! also compiles on the pinned stable toolchain.
#![no_main]
#[path = "body/sshd_policy.rs"]
mod body;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = body::run(data);
});
