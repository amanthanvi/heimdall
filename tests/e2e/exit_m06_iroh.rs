//! ⟨M06 W5 U7; W5 `w5d`⟩ A26's exit journey through the **real binary built with the Iroh
//! transport** (m06-plan §1 U7, §3 row "A26"). Cargo test target `e2e_exit_m06_iroh`,
//! hosted by `heimdall`, `required-features = ["iroh"]`. Loopback only: no container, no
//! relay, no non-loopback bind.
//!
//! One test, named as the native harness indexes it: [`a26_iroh_routes_trust`]
//! (`exit_m06/a26.rs`). It runs real Iroh traffic between two installations of this host
//! with the debug build's **fixture K_iroh store** (`HEIMDALL_TEST_IROH_KEY_STORE`), so
//! every `m06 observation: a26 <step>: <result>` line ends with `key_store=fixture_store`:
//! mechanism evidence with the product binary, never product persistence of K_iroh (the
//! module's header and `NOT-COVERED.md` say what stays blocked). The world and its
//! isolation are `exit_m06.rs`'s.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    missing_docs
)]
#![cfg(unix)]

#[path = "exit_m06/world.rs"]
mod world;

#[path = "exit_m06/m06.rs"]
mod m06;

#[path = "exit_m06/a26.rs"]
mod a26;

#[test]
fn a26_iroh_routes_trust() {
    a26::journey();
}

// ⟨M06 W5 `w5m`⟩ M03's exit world, shared (not copied) as `exit_m06` shares it: a
// controller whose catalog the product's own commands built.
#[allow(clippy::print_stdout, clippy::print_stderr)]
#[path = "exit_m03/world.rs"]
mod m03world;
#[allow(clippy::print_stdout, clippy::print_stderr)]
#[path = "exit_m03/procs.rs"]
mod procs;

// (`route_add` is the other target's: it needs no Iroh build.)
#[allow(dead_code)]
#[path = "exit_m06/widening_local.rs"]
mod widening_local;

/// ⟨M06 W5 `w5m`⟩ `transport adopt-roost` on a controller, through the product CLI: refused
/// unattended, a local decision record on a terminal, and the attended `decision approve`
/// adds the roost with its recorded consent (ADR-0006 §18.9 item 8; ADR-0012 §2.8).
#[test]
fn local_widening_adopt_roost_on_a_controller() {
    widening_local::adopt_roost();
}

// ⟨M06 W5 `w5o` item 7⟩ The controller world's ordinary-alias logins (`ordinary_login`,
// `alias_block`, `inspected`); the journey of that file is the other target's.
#[allow(dead_code)]
#[path = "exit_m06/routes.rs"]
mod routes;

#[path = "exit_m06/iroh_alias.rs"]
mod iroh_alias;

/// ⟨M06 W5 `w5o` item 7⟩ A26's Iroh leg through a **projected alias**: a controller
/// installation whose catalog the product's commands built dials over Iroh with ordinary
/// `ssh <alias>`, fails over to its direct route, and is refused on a wrong host.
#[test]
fn a26_iroh_through_a_projected_alias() {
    iroh_alias::journey();
}
