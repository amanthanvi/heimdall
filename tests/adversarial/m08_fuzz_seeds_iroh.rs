//! The `iroh_policy` fuzz target's body over its committed seeds (ADR-0014 §2.1 boundary 14;
//! `fuzz/README.md`): as `m08_fuzz_seeds.rs`, for the one body that needs
//! `heimdall-transport-iroh`, which `heimdall-app` (and so the other host) must never import.
//!
//! Cargo test target `adversarial_m08_fuzz_seeds_iroh`, hosted by `heimdall-transport-iroh`.
//! Pure: no file is read at run time (the seeds are embedded, `m08_fuzz_seed_list.rs`), no
//! socket is opened and no endpoint is built (the default build has no iroh).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../../fuzz/fuzz_targets/body/iroh_policy.rs"]
mod iroh_policy;

use iroh_policy::Reached;

// Shared with `m08_fuzz_seeds.rs`, whose tests use `seed` too.
#[allow(dead_code)]
#[path = "m08_fuzz_seed_list.rs"]
mod seed_list;

#[test]
fn iroh_policy_seeds_reach_each_refusal_and_an_approval() {
    for (name, bytes) in seed_list::seeds("iroh_policy") {
        let want = match name {
            "loopback_direct" | "custom_relays_hints" | "interface_fallback" => {
                Reached::RouteApproved
            }
            "hint_outside_policy" | "interface_other_family" => Reached::RouteRefused,
            "n0_public" => Reached::PolicyRefused,
            other => panic!("an unlisted seed {other}"),
        };
        assert_eq!(iroh_policy::run(bytes), want, "{name}");
    }
}
