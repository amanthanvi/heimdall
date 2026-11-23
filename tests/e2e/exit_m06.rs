//! ⟨M06 W5 U7⟩ The M06 exit journeys through the **real binaries** (m06-plan §1 U7, §3
//! "Exit mapping"; spec A24, A25, A07; plan §5 M06 T06). Cargo test target `e2e_exit_m06`,
//! hosted by `heimdall`. A26's journey needs the Iroh transport and is `e2e_exit_m06_iroh`.
//!
//! Each test is one §3 row, named as the native harness indexes it, and prints one
//! `m06 observation: <case> <step>: <result>` line per step:
//!
//! * `a24_runner_without_controller` (`exit_m06/a24.rs`);
//! * `a25_roles_invitations_decisions` (`exit_m06/a25.rs`);
//! * `a07_runner_disconnected` (`exit_m06/a07.rs`);
//! * `t06_second_controller` (`exit_m06/t06.rs`);
//! * ⟨`w5f`⟩ `a25_pairing_invite_join_through_the_product_cli` (`exit_m06/pairing.rs`, over
//!   `exit_m06/cli_world.rs` and M03's exit world): pairing, invitation and join through
//!   the product CLI;
//! * ⟨`w5f`, `w5n`⟩ `a26_routes_and_host_trust_without_iroh` (`exit_m06/routes.rs`): A26's
//!   routes and host trust without Iroh, through ordinary `ssh <alias>` and the projected
//!   route helper.
//!
//! **What runs.** The real `heimdall` (`HEIMDALL_E2E_BIN`, else `CARGO_BIN_EXE_heimdall`)
//! on both sides: a runner (`remote init` on a pseudo-terminal, `service run --runner`) and
//! a controller (`service run`, hosting the sync and issuance driver and the production
//! `internal issuer` child over a scratch state database and a scratch secret store), the
//! system OpenSSH client, and unprivileged fixture sshds on 127.0.0.1 (the runner's
//! management sshd and the onward destinations). The world is `exit_m06/world.rs`, shared
//! with `environment_runner_m06.rs`.
//!
//! **What does not.** One host stands for both the runner and the controller. Every step of
//! a §3 row that needs a second host, a container, a Windows controller, a lifecycle
//! environment or an owner input is **not run and not claimed** here: the unit's
//! `NOT-COVERED.md` lists each with the exact missing platform or input. Each module's
//! header says which steps of its row it drives and which it does not. Where the suite
//! seeds a record instead of driving the command that writes it, the observation says
//! `seeded`.
//!
//! **Platforms.** `cfg(unix)`: the runner is Unix-only in V1 (m06-plan §5), so on Windows
//! this target holds no test, and the Windows controller rows need the runner on another
//! host. Where no fixture sshd can start, a test prints `journey: blocked (<reason>)` and
//! asserts nothing.
//!
//! **Isolation** is the world's: cleared environments, scratch `HOME`, `HEIMDALL_HOME` and
//! `HEIMDALL_TEST_SSH_HOME` for every process, per-run keys and host keys, no
//! `SSH_AUTH_SOCK` for any fixture `ssh`, loopback listeners only; only the processes the
//! suite started are stopped, through their own handles or `service stop` on their own
//! scratch home.
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

#[path = "exit_m06/a24.rs"]
mod a24;

#[test]
fn a24_runner_without_controller() {
    a24::journey();
}

#[path = "exit_m06/a07.rs"]
mod a07;

#[test]
fn a07_runner_disconnected() {
    a07::journey();
}

#[path = "exit_m06/t06.rs"]
mod t06;

#[test]
fn t06_second_controller() {
    t06::journey();
}

#[path = "exit_m06/a25.rs"]
mod a25;

#[test]
fn a25_roles_invitations_decisions() {
    a25::journey();
}

#[path = "exit_m06/connect_runner.rs"]
mod connect_runner;

/// ⟨M06 W5 `w5i`⟩ `connect` on a runner goes through the clean launch (ADR-0012 §4 item 5).
#[test]
fn connect_on_a_runner_is_a_clean_launch() {
    connect_runner::journey();
}

// ⟨M06 W5 `w5f`⟩ M03's exit world, shared (not copied) as `exit_m05` shares it: the first
// controller of the journeys that pair through the product CLI (`exit_m06/cli_world.rs`).
// (Their fixture lines are printed, as in the M03 and M05 exit targets.)
#[allow(clippy::print_stdout, clippy::print_stderr)]
#[path = "exit_m03/world.rs"]
mod m03world;
#[allow(clippy::print_stdout, clippy::print_stderr)]
#[path = "exit_m03/procs.rs"]
mod procs;

#[path = "exit_m06/cli_world.rs"]
mod cli_world;

#[path = "exit_m06/pairing.rs"]
mod pairing;

/// ⟨M06 W5 `w5f`⟩ Pairing, invitation, join, `revoke-client` and `remove` through the
/// product CLI (A25's fixture is the real pairing path).
#[test]
fn a25_pairing_invite_join_through_the_product_cli() {
    pairing::journey();
}

#[path = "exit_m06/routes.rs"]
mod routes;

/// ⟨M06 W5 `w5f`, `w5n`⟩ A26's routes and host trust without Iroh, through ordinary `ssh
/// <alias>`: the projected route helper and catalog pin, a jump and a direct route to one
/// destination, a wrong host refused and never retried on another route, failover before
/// identification, a substituted pin refused, and `host_pin_defeated`.
#[test]
fn a26_routes_and_host_trust_without_iroh() {
    routes::journey();
}

// (`adopt_roost` is the `iroh` target's: the transport forms refuse without the feature.)
#[allow(dead_code)]
#[path = "exit_m06/widening_local.rs"]
mod widening_local;

/// ⟨M06 W5 `w5m`⟩ A widening `route add` on a controller, through the product CLI: refused
/// unattended, a local decision record on a terminal, a retry returns it, and the attended
/// `decision approve` applies it (ADR-0006 §18.9 item 8).
#[test]
fn local_widening_route_add_on_a_controller() {
    widening_local::route_add();
}

#[path = "exit_m06/lift.rs"]
mod lift;

/// ⟨M06 W5 `w5m` L4⟩ A delivered `all` cutoff on a runner with no standing policy: the
/// owner's acknowledgement alone resumes nothing; the runner's own attended `access cutoff
/// --clear --all` lifts it (ADR-0012 §7.4; ADR-0006 §18.9 item 4).
#[test]
fn a_delivered_cutoff_on_a_policy_less_runner_is_lifted_locally() {
    lift::journey();
}
