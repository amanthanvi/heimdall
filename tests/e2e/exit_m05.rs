//! ⟨M05 wave 4, U10⟩ The M05 exit suite through the **real binary** (`HEIMDALL_E2E_BIN`,
//! else `CARGO_BIN_EXE_heimdall`), its CLI-started runtime and its **real** `internal
//! issuer` child, the system OpenSSH client, `scp` and Git, against the world's fixture
//! `sshd` (m05-plan §1 U10, §3; orchestrator ruling I-16). Cargo test target
//! `e2e_exit_m05`, hosted by `heimdall`.
//!
//! **Built on M03's exit world, not a copy of it** (ruling I-16): [`world`], [`worker`]
//! and [`procs`] are `tests/e2e/exit_m03/`'s own files, extended there by additive options
//! and helpers (shared servers, the personal default at setup, `run` in a directory, a
//! sequence of typed answers; the worker's `env_names`, `agent_frames` and own-endpoint
//! login). The M05 helpers are [`m05`].
//!
//! The rows (each a test; m05-plan §3):
//! * [`a02`]: A02, a normal working week, and "zero additional same-authority prompts";
//! * [`a16`]: A16, "defaults don't redirect running work" (two environments, one OS
//!   user), and A04's default row;
//! * [`a28`]: A28's managed rows (the real-binary versions of
//!   `managed_store::live_tests::delegation_m05`);
//! * [`u5`]: ordinary `ssh` activates the personal default (U5; rulings I-2, I-13, I-20);
//! * [`pending_e5`]: the assertion that waited for M03 exit build E5 (a revoked or stopped
//!   managed grant reaches `revoked` after its certificate's residual); E5 is on this base,
//!   so it runs.
//!
//! **Platforms.** Every row is `cfg(any(unix, windows))`. Windows runs need the harness's
//! WSL fixture sshd (`HM_FIXTURE_SSHD_*` with its enrollment registry, and
//! `HM_FIXTURE_SSHD_STRICT_*` where a row needs a second server), the in-box OpenSSH
//! client and the ConPTY console; without a fixture sshd a test fails naming it, never
//! skips. Windows variants exist only where Windows behaviour differs: no shell hook (owner
//! question Q6; A02 uses `run`, U5 the ordinary `ssh` alone), the named-pipe signing
//! endpoint (the client options and the worker's endpoint), and default activation through
//! the Windows signer (the same identities path, reached over the pipe).
//!
//! **Isolation** is the world's (`exit_m03/world.rs`): a cleared environment, scratch
//! `HOME` and Heimdall homes, stdin closed or a terminal, the decoy agent at
//! `SSH_AUTH_SOCK`; no owner key, agent, keychain or `~/.ssh` is touched. Every runtime is
//! the world's, stopped through `service stop` on its own scratch home, or by its exact PID
//! (checked against its start time) where a row crashes it; workers and stand-in shells are
//! stopped through their own handles. Each started PID is printed as `m05 started-pid …`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    missing_docs
)]
#![cfg_attr(not(any(unix, windows)), allow(dead_code, unused_imports))]

#[path = "exit_m03/procs.rs"]
mod procs;
#[path = "exit_m03/worker.rs"]
mod worker;
#[path = "exit_m03/world.rs"]
mod world;

#[path = "exit_m05/m05.rs"]
mod m05;

#[path = "exit_m05/a02.rs"]
mod a02;
#[path = "exit_m05/a16.rs"]
mod a16;
#[path = "exit_m05/a28.rs"]
mod a28;
#[path = "exit_m05/pending_e5.rs"]
mod pending_e5;
#[path = "exit_m05/u5.rs"]
mod u5;

use std::path::Path;

/// The worker's entry when this binary is re-executed under `heimdall run`
/// ([`world::World::spawn_run`]); a no-op in the suite itself (no instructions).
#[test]
fn worker_process_entry() {
    if let Some(path) = std::env::var_os(world::WORKER_ENV) {
        worker::run(Path::new(&path));
    }
}
