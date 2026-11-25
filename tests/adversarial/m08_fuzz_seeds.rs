//! The M08 U1b fuzz targets' bodies over their committed seeds (ADR-0014 §2.1 boundaries 12
//! to 15; `fuzz/README.md`).
//!
//! The fuzz build runs only in the campaign container (`fuzz/run-campaign.sh`, a pinned
//! nightly), so this test compiles each body from the very file its target includes
//! (`fuzz/fuzz_targets/body/<target>.rs`) on the pinned stable toolchain, feeds it every
//! committed seed (`fuzz/seeds/<target>/`, embedded at compile time: `m08_fuzz_seed_list.rs`),
//! and checks that the named seeds reach the code they were written for. Each body asserts its
//! own invariants, so a seed that breaks one fails here as it would crash the target.
//!
//! Cargo test target `adversarial_m08_fuzz_seeds`, hosted by `heimdall-remote` (it has every
//! edge these bodies use). `iroh_policy`'s body is hosted by `heimdall-transport-iroh`
//! (`m08_fuzz_seeds_iroh.rs`), since `heimdall-app` must never import that crate. Pure: no
//! file is read at run time (the seeds and the campaign's manifests are embedded), and nothing
//! is started but an in-process runtime stub.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../../fuzz/fuzz_targets/body/page_select.rs"]
mod page_select;
#[path = "../../fuzz/fuzz_targets/body/remote_bridge.rs"]
mod remote_bridge;
#[path = "../../fuzz/fuzz_targets/body/remote_join.rs"]
mod remote_join;
#[path = "../../fuzz/fuzz_targets/body/route_preident.rs"]
mod route_preident;
#[path = "../../fuzz/fuzz_targets/body/route_ssh_g.rs"]
mod route_ssh_g;
#[path = "../../fuzz/fuzz_targets/body/sshd_policy.rs"]
mod sshd_policy;

use heimdall_app::routes::failover::Scan;
use heimdall_remote::bridge::{BridgeEnd, Violation};
use heimdall_remote::invitations::JoinDecision;
use heimdall_remote::roles::Refusal;

#[path = "m08_fuzz_seed_list.rs"]
mod seed_list;

use seed_list::{seed, seeds};

/// Each target the campaign runs has seeds, a body and a `TARGETS` entry whose length cap is
/// above every seed (`fuzz/run-campaign.sh`, embedded at compile time).
#[test]
fn every_new_target_is_listed_with_a_cap_above_its_seeds() {
    let script = include_str!("../../fuzz/run-campaign.sh");
    let manifest = include_str!("../../fuzz/Cargo.toml");
    for target in [
        "remote_bridge",
        "remote_join",
        "sshd_policy",
        "route_preident",
        "iroh_policy",
        "page_select",
        "route_ssh_g",
    ] {
        let cap: usize = script
            .split_whitespace()
            .find_map(|w| w.trim_matches('"').strip_prefix(&format!("{target}:")))
            .unwrap_or_else(|| panic!("{target} is in TARGETS"))
            .parse()
            .unwrap();
        for (name, bytes) in seeds(target) {
            assert!(
                bytes.len() <= cap,
                "{target}/{name} fits under max_len {cap}"
            );
        }
        assert!(
            manifest.contains(&format!("path = \"fuzz_targets/{target}.rs\"")),
            "{target} is a [[bin]] of fuzz/Cargo.toml"
        );
    }
}

#[test]
fn remote_bridge_seeds_reach_the_relay_and_each_closing_rule() {
    for (name, bytes) in seeds("remote_bridge") {
        assert!(remote_bridge::run(bytes).is_some(), "{name}");
    }
    let end = |name: &str| remote_bridge::run(seed("remote_bridge", name)).unwrap();
    assert_eq!(end("hello_then_request"), BridgeEnd::RemoteClosed);
    assert_eq!(
        end("identity_frame"),
        BridgeEnd::Violation(Violation::IdentityAssertion)
    );
    assert_eq!(
        end("second_hello"),
        BridgeEnd::Violation(Violation::SecondHello)
    );
    assert_eq!(
        end("hello_naming_a_client"),
        BridgeEnd::Violation(Violation::IdentityAssertion)
    );
    assert_eq!(
        end("oversized_length"),
        BridgeEnd::Violation(Violation::TooLarge)
    );
}

#[test]
fn remote_join_seeds_activate_only_the_matching_join() {
    for (name, bytes) in seeds("remote_join") {
        let _ = remote_join::run(bytes);
        let _ = name;
    }
    let decide = |name: &str| remote_join::run(seed("remote_join", name));
    assert!(matches!(
        decide("join_matching"),
        Some(JoinDecision::Activate(_))
    ));
    assert_eq!(
        decide("join_wrong_generation"),
        Some(JoinDecision::Refuse(Refusal::BindingMismatch))
    );
    assert_eq!(
        decide("join_unadmitted_endpoint"),
        Some(JoinDecision::Refuse(Refusal::InvalidRequest))
    );
    assert_eq!(decide("activation_probe"), None, "not a join");
}

#[test]
fn sshd_policy_seeds_verify_only_the_devbox_shape() {
    let verified: Vec<(&str, Option<bool>)> = seeds("sshd_policy")
        .into_iter()
        .map(|(n, b)| (n, sshd_policy::run(b)))
        .collect();
    for (name, v) in &verified {
        let want = matches!(*name, "devbox_verified" | "openssh_10_spelling");
        assert_eq!(*v, Some(want), "{name}");
    }
}

#[test]
fn route_preident_seeds_identify_or_overflow_at_the_bounds() {
    let scan = |name: &str| route_preident::run(seed("route_preident", name));
    for (name, bytes) in seeds("route_preident") {
        let _ = (name, route_preident::run(bytes));
    }
    assert!(matches!(
        scan("banner_then_identification"),
        Scan::Identified { .. }
    ));
    assert_eq!(scan("identification_only"), Scan::Identified { end: 20 });
    assert_eq!(scan("too_many_lines"), Scan::Overflow);
    assert_eq!(scan("overlong_identification"), Scan::Overflow);
    assert_eq!(scan("no_line_end"), Scan::Overflow);
}

#[test]
fn page_select_seeds_decode_their_forms() {
    let decoded = |name: &str| page_select::run(seed("page_select", name));
    for (name, bytes) in seeds("page_select") {
        let _ = (name, page_select::run(bytes));
    }
    assert!(decoded("token").token);
    assert!(decoded("page_request").page);
    assert_eq!(decoded("select").select, Some(true));
    assert_eq!(decoded("empty_select").select, Some(false));
    assert!(
        !decoded("bad_token").page,
        "a bad token refuses the page request"
    );
}

#[test]
fn route_ssh_g_seeds_verify_one_proxy_each() {
    let verified = |name: &str| route_ssh_g::run(seed("route_ssh_g", name));
    for (name, bytes) in seeds("route_ssh_g") {
        let _ = (name, route_ssh_g::run(bytes));
    }
    for name in ["direct_pinned", "helper_pinned", "jump_pinned"] {
        assert_eq!(verified(name), Some(1), "{name}");
    }
    assert_eq!(verified("accept_new_defeats_the_pin"), Some(0));
    assert_eq!(verified("repeated_alias"), Some(0));
}
