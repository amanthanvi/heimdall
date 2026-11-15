# P8 worklog, round 15 (W5-I01; F2; Windows coverage; Linux passphrase test)
Base 40a8d1d4. K4 on devbox issuer diagnosis (crates/issuer/**): coordinate devbox runs.

## P9 (takeover from P8), 2026-11-15
- Read AGENTS.md, r12 brief, ADR §17.33-17.37, wave5-final W5-I01. Reconciling P8's partial diff (purge_sweep +512, uninstall_cmd +252, claims +18).
- Host build of P8's tree: exit 0; 47 round-13/14/15 tests passed (exit 0). Windows clippy after gating `read_with_wal` #[cfg(unix)] (its users are Unix-only census probes): exit 0.
- Extended without-copy probe with the review's empty marker; refined RESIDUALS texts.
- Revert proofs R1-R6 (Unix recover_unit copy precondition, ops.check, binding compare, inode loop, Unit::delete verify, F2 -wal condition): each 101 reverted, sha restored, 0 rerun.
- fmt 0; purge_sweep:: 29 ok exit 0; uninstall_cmd:: 67 ok exit 0; runtime integration 60/0 exit 0; store 22/0; domain 127/0; contract 133/0 (all exit 0)
- e2e_cli_m03 69/0/3ign exit 0; e2e_cli_m02 uninstall 8/0 exit 0; claims_table exit 0; host clippy exit 0
- clippy-windows exit 0 (final tree)
- linux-xcheck -p heimdall -p heimdall-runtime -p heimdall-store: exit 0 (15m27s). Cargo.lock diff empty. Scratch dir removed.
- target: debug 151G, x86_64-pc-windows-gnu 3.6G (kept), x86_64-unknown-linux-gnu 1.3G (kept for re-runs); flagged to orchestrator.
- DONE: report in .m03-wave5-r15-P8-DONE.md.
