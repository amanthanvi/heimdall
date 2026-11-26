//! The committed seeds of M08 U1b's fuzz targets (`fuzz/seeds/<target>/<name>`), embedded at
//! compile time for `m08_fuzz_seeds.rs` and `m08_fuzz_seeds_iroh.rs`, which include this file.
//! Embedded, not read at run time: the native runs ship test binaries with a repository copy
//! (`HM_REPO_ROOT`) that holds no `fuzz/` directory, and `include_bytes!` is not a run-time
//! read of the repository (`heimdall_testkit::repo`). A seed added to a directory and not here
//! is still in the campaign's corpus; it is only not replayed by these tests.

/// `(target, name, bytes)` for each listed seed, read by `include_bytes!` from
/// `fuzz/seeds/<target>/<name>`.
macro_rules! seeds {
    ($($target:literal: [$($name:literal),* $(,)?]),* $(,)?) => {
        &[$($((
            $target,
            $name,
            include_bytes!(concat!("../../fuzz/seeds/", $target, "/", $name)) as &[u8],
        ),)*)*]
    };
}

/// Every `(target, name, bytes)`, by target, then name.
pub const SEEDS: &[(&str, &str, &[u8])] = seeds! {
    "iroh_policy": [
        "custom_relays_hints",
        "hint_outside_policy",
        "interface_fallback",
        "interface_other_family",
        "loopback_direct",
        "n0_public",
    ],
    "page_select": ["bad_token", "empty_select", "page_request", "select", "token"],
    "remote_bridge": [
        "hello_naming_a_client",
        "hello_then_request",
        "identity_frame",
        "oversized_length",
        "second_hello",
    ],
    "remote_join": [
        "activation_probe",
        "join_matching",
        "join_unadmitted_endpoint",
        "join_wrong_generation",
    ],
    "route_preident": [
        "banner_then_identification",
        "identification_only",
        "no_line_end",
        "overlong_identification",
        "too_many_lines",
    ],
    "route_ssh_g": [
        "accept_new_defeats_the_pin",
        "direct_pinned",
        "helper_pinned",
        "jump_pinned",
        "repeated_alias",
    ],
    "sshd_policy": [
        "devbox_verified",
        "old_version",
        "openssh_10_spelling",
        "permituserenvironment_yes",
    ],
};

/// Every seed of `target`, by name; at least one.
pub fn seeds(target: &str) -> Vec<(&'static str, &'static [u8])> {
    let out: Vec<(&'static str, &'static [u8])> = SEEDS
        .iter()
        .filter(|(t, _, _)| *t == target)
        .map(|(_, n, b)| (*n, *b))
        .collect();
    assert!(!out.is_empty(), "{target} has seeds");
    out
}

/// The seed `name` of `target`.
pub fn seed(target: &str, name: &str) -> &'static [u8] {
    seeds(target)
        .into_iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("{target} has the seed {name}"))
        .1
}
