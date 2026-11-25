//! Boundary 12 (ADR-0014 §2.1), the M06 route checks' `ssh -G` reader: what `ssh -G` prints
//! for a projected route alias, under a configuration an attacker may have written, read by
//! the public `verify_effective` (`heimdall_registry::routes`, re-exported as
//! `heimdall_app::routes::verify_effective`) against the three proxy expectations a route
//! can have (direct, the route helper, a native jump).
//!
//! The invariants (ADR-0012 §5.2): a verified output prints `stricthostkeychecking` exactly
//! once with `yes` (or `true`), and no output verifies for two different proxies.
//!
//! Shared by the fuzz target `route_ssh_g` and the seed test
//! `tests/adversarial/m08_fuzz_seeds.rs`.

use heimdall_app::routes::{ExpectedProxy, PinExpectation, verify_effective};

/// The fixture expectations: one pin, one owned control path, each proxy kind.
pub fn expectations() -> [PinExpectation; 3] {
    [
        ExpectedProxy::None,
        ExpectedProxy::Helper("/hm/bin/heimdall route connect --alias lab".to_owned()),
        ExpectedProxy::Jump("hm-jump".to_owned()),
    ]
    .map(|proxy| PinExpectation {
        host_key_alias: "hm-dest-0101".to_owned(),
        pin_file: "/hm/home/.ssh/heimdall/known_hosts".to_owned(),
        owned_control_path: Some("/hm/run/b/mux".to_owned()),
        proxy,
    })
}

/// How many of [`expectations`] the output in `data` verifies; `None` for input that is not
/// UTF-8, which the reader refuses before parsing. Panics (a finding) when an invariant breaks.
pub fn run(data: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(data).ok()?;
    let verified = expectations()
        .iter()
        .filter(|e| verify_effective(text, e).is_ok())
        .count();
    if verified > 0 {
        let strict: Vec<&str> = text
            .lines()
            .map(|l| l.trim_end_matches('\r'))
            .filter_map(|l| {
                let (k, v) = l.split_once(' ').unwrap_or((l, ""));
                k.eq_ignore_ascii_case("stricthostkeychecking").then_some(v)
            })
            .collect();
        assert!(
            matches!(strict.as_slice(), ["yes" | "true"]),
            "verified without exactly one strict host key checking line"
        );
    }
    assert!(
        verified <= 1,
        "an output verified for two different proxies"
    );
    Some(verified)
}
