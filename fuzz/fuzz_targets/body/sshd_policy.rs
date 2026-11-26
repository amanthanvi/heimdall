//! Boundary 13 (ADR-0014 §2.1), the `sshd -T` verifier: a runner's sshd banner (the first
//! line) and its effective configuration as `sshd -T` prints it (the rest), read by the
//! public `heimdall_remote::sshd_policy::{verify, OpensshVersion::parse_banner}` for a fixture
//! account, with and without a known login shell. A verified policy must lie inside the
//! reader's own bounds (256 KiB, 8192 lines).
//!
//! Shared by the fuzz target `sshd_policy` and the seed test
//! `tests/adversarial/m08_fuzz_seeds.rs`.

use heimdall_remote::sshd_policy::{
    Account, MAX_LINES, MAX_OUTPUT_BYTES, OpensshVersion, PolicyVerdict, verify,
};

/// Whether the policy in `data` verifies for the fixture account (with its login shell);
/// `None` for input that is not UTF-8, which the reader never sees.
pub fn run(data: &[u8]) -> Option<bool> {
    let text = std::str::from_utf8(data).ok()?;
    let (banner, effective) = text.split_once('\n').unwrap_or((text, ""));
    let _ = OpensshVersion::parse_banner(banner);
    let account = Account {
        user: "runner",
        home: "/home/runner",
        login_shell: Some("/bin/bash"),
    };
    let verified = matches!(
        verify(effective, banner, &account),
        PolicyVerdict::Verified(_)
    );
    let _ = verify(
        effective,
        banner,
        &Account {
            login_shell: None,
            ..account
        },
    );
    if verified {
        assert!(
            effective.len() <= MAX_OUTPUT_BYTES && effective.lines().count() <= MAX_LINES,
            "a policy verified outside the reader's bounds"
        );
    }
    Some(verified)
}
