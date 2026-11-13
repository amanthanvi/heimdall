# M03 wave 4, round 5 — worker Y-C (W4-C01) worklog

Goal: a released, re-issued, slotless managed binding's endpoint and files are removed
(at release, or by the next supervisor pass, which `managed_cleanup_owed` lists until
done); the still-referenced grant keeps K_env and the child still signs.

## Decisions
- C-1. Generations: every resource generation of a binding of grant G is in
  `1..=max(instances(G), 1)` (a preparation and a follower write
  `BINDING_GENERATION` = 1; a re-issue writes `max(instances, 2)` with its own new
  instance already counted, and instances only grow). The release clears each of
  them through the port (`ManagedEffects::clear`, generation-fenced, idempotent).
  The supervisor pass clears the same range plus every generation found on disk by
  marker plus this instance's last materialization's, then verifies none is left.
- C-2. Durable, discoverable retry without a migration: the release transaction of a
  managed binding records a meta row `managed_released_binding_cleanup:<binding>`
  (precedent: `cleanup_intent:`, `grant_degradation:` meta rows).
  `managed_cleanup_owed` lists the binding's grant while the row exists; the
  supervisor's pass (`StoreCleanup::clean_bindings`) deletes it only after the
  binding's endpoint and files are verified gone (and its slots freed).
- C-3. K_env untouched: `ManagedEffects::clear` only detaches the binding; the pass
  destroys keys only for a terminal grant (unchanged).

## Progress / commands
- Regressions (`crates/runtime/src/managed_store/live_tests/cleanup.rs`, real Live harness: store, vault,
  signer table, `ManagedEffectsImpl`, `EndpointRegistry`, fixture issuer, real child delegation, restart in
  the same boot, the real `managed_reissue_pass`, `Supervisor::ended_slot_pass`):
  - `released_reissued_slotless_binding_loses_endpoint_and_files_while_grant_lives`
  - `failed_release_cleanup_of_reissued_slotless_binding_is_retried_until_clean` (injected failure: the
    re-issued generation's binding directory 0o500; two passes retry, still owed; restored 0o700, next pass
    cleans and records done)
  Helpers: `delegated_parent(.., bind)` (`parent_with_child_delegation` now delegates to it with `bind=true`),
  `reissued_slotless_parent`, `grant_kept_and_child_signs`.

| Run | Command | Exit | Observed |
|---|---|---|---|
| base (fix absent) | `cargo test -p heimdall-runtime --lib live_tests::cleanup` | 101 | `released re-issued slotless binding (generation 2): endpoint_retained=true, files_retained=true, cleanup_owed=0`; retry test: `the endpoint is removed first` |
| fixed | same | 0 | 7 passed |
| R1: release clears only gen 1 (`..=BINDING_GENERATION.min(bound)`) | same | 101 | `... (generation 2): endpoint_retained=true, files_retained=true, cleanup_owed=1`; retry test fails at `the endpoint is removed first` |
| R2: release records no obligation | same | 101 | both new tests: owed `left: [] right: [grant]` |
| R3: `managed_cleanup_owed` ignores the release obligation rows | same | 101 | both new tests: owed `left: [] right: [grant]` |
| R4: the pass never records done | same | 101 | 4 fail (`nothing owed once done`, `recorded done`, and the two W4-R07/R08 tests' `owed` empty asserts) |
| restored after each | grep REVERT-R → none | — | — |

R1 used a whole-file copy/restore of `managed_driver_m03.rs` (possible clobber of a concurrent Y-S edit,
reported to the integrator and under Requests); R2–R4 were exact in-place substitutions undone in place.

| Gate | Exit |
|---|---|
| `cargo test -p heimdall-runtime` (all targets incl. lib) | 0 |
| `cargo test -p heimdall --test e2e_managed_m03 --test e2e_run_m02` | 0 |
| `cargo test -p heimdall-app --tests` | 0 |
| `cargo test -p heimdall-store` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 (before the server restart) |
| `rustfmt --edition 2024 --check` on my six files | 0 each |

After the server restart (state re-checked: all edits intact, no revert marker, `release_checked` unchanged):
| Gate (current tree) | Exit |
|---|---|
| `bash tools/validation/clippy-windows.sh` | 0 |
| `bash tools/validation/linux-xcheck.sh -p heimdall-runtime` | 0 |
| `rustfmt --edition 2024 --check` (6 files; `cleanup.rs` formatted first) | 0 each |
| `cargo clippy -p heimdall-runtime -p heimdall-store -p heimdall-adapters -p heimdall-app --all-targets -- -D warnings` | 0 |
| `cargo test -p heimdall-runtime --lib` | 0 (58 passed) |
| `cargo clippy --workspace --all-targets -- -D warnings` re-run | not completed: three attempts were stopped by the harness's 30-min background cap (build-lock waits behind Y-W's hour-long run, then checking `heimdall`); its pre-restart run on my code exited 0 and the only later changes to my files are rustfmt whitespace and a doc comment |
